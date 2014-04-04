# -*- coding: utf-8 -*-
# test_imap.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test case for leap.email.imap.server
TestCases taken from twisted tests and modified to make them work
against SoledadBackedAccount.

@authors: Kali Kaneko, <kali@leap.se>
XXX add authors from the original twisted tests.

@license: GPLv3, see included LICENSE file
"""
# XXX review license of the original tests!!!
from email import parser

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import os
import types
import tempfile
import shutil
import time

from itertools import chain


from mock import Mock
from nose.twistedtools import deferred, stop_reactor
from unittest import skip


from twisted.mail import imap4
from twisted.protocols import loopback
from twisted.internet import defer
from twisted.trial import unittest
from twisted.python import util, log
from twisted.python import failure

from twisted import cred
import twisted.cred.error
import twisted.cred.checkers
import twisted.cred.credentials
import twisted.cred.portal


# import u1db

from leap.common.testing.basetest import BaseLeapTest
from leap.mail.imap.account import SoledadBackedAccount
from leap.mail.imap.mailbox import SoledadMailbox
from leap.mail.imap.memorystore import MemoryStore
from leap.mail.imap.messages import MessageCollection
from leap.mail.imap.server import LeapIMAPServer

from leap.soledad.client import Soledad
from leap.soledad.client import SoledadCrypto

TEST_USER = "testuser@leap.se"
TEST_PASSWD = "1234"


def strip(f):
    return lambda result, f=f: f()


def sortNest(l):
    l = l[:]
    l.sort()
    for i in range(len(l)):
        if isinstance(l[i], types.ListType):
            l[i] = sortNest(l[i])
        elif isinstance(l[i], types.TupleType):
            l[i] = tuple(sortNest(list(l[i])))
    return l


def initialize_soledad(email, gnupg_home, tempdir):
    """
    Initializes soledad by hand

    :param email: ID for the user
    :param gnupg_home: path to home used by gnupg
    :param tempdir: path to temporal dir
    :rtype: Soledad instance
    """

    uuid = "foobar-uuid"
    passphrase = u"verysecretpassphrase"
    secret_path = os.path.join(tempdir, "secret.gpg")
    local_db_path = os.path.join(tempdir, "soledad.u1db")
    server_url = "http://provider"
    cert_file = ""

    class MockSharedDB(object):

        get_doc = Mock(return_value=None)
        put_doc = Mock()
        lock = Mock(return_value=('atoken', 300))
        unlock = Mock(return_value=True)

        def __call__(self):
            return self

    Soledad._shared_db = MockSharedDB()

    _soledad = Soledad(
        uuid,
        passphrase,
        secret_path,
        local_db_path,
        server_url,
        cert_file)

    return _soledad


class TestRealm:

    """
    A minimal auth realm for testing purposes only
    """
    theAccount = None

    def requestAvatar(self, avatarId, mind, *interfaces):
        return imap4.IAccount, self.theAccount, lambda: None


#
# Simple IMAP4 Client for testing
#


class SimpleClient(imap4.IMAP4Client):

    """
    A Simple IMAP4 Client to test our
    Soledad-LEAPServer
    """

    def __init__(self, deferred, contextFactory=None):
        imap4.IMAP4Client.__init__(self, contextFactory)
        self.deferred = deferred
        self.events = []

    def serverGreeting(self, caps):
        self.deferred.callback(None)

    def modeChanged(self, writeable):
        self.events.append(['modeChanged', writeable])
        self.transport.loseConnection()

    def flagsChanged(self, newFlags):
        self.events.append(['flagsChanged', newFlags])
        self.transport.loseConnection()

    def newMessages(self, exists, recent):
        self.events.append(['newMessages', exists, recent])
        self.transport.loseConnection()


class IMAP4HelperMixin(BaseLeapTest):

    """
    MixIn containing several utilities to be shared across
    different TestCases
    """

    serverCTX = None
    clientCTX = None

    @classmethod
    def setUpClass(cls):
        """
        TestCase initialization setup.
        Sets up a new environment.
        Initializes a SINGLE Soledad Instance that will be shared
        by all tests in this base class.
        This breaks orthogonality, avoiding us to use trial, so we should
        move away from this test design. But it's a quick way to get
        started without knowing / mocking the soledad api.

        We do also some duplication with BaseLeapTest cause trial and nose
        seem not to deal well with deriving classmethods.
        """
        cls.old_path = os.environ['PATH']
        cls.old_home = os.environ['HOME']
        cls.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        cls.home = cls.tempdir
        bin_tdir = os.path.join(
            cls.tempdir,
            'bin')
        os.environ["PATH"] = bin_tdir
        os.environ["HOME"] = cls.tempdir

        # Soledad: config info
        cls.gnupg_home = "%s/gnupg" % cls.tempdir
        cls.email = 'leap@leap.se'

        # initialize soledad by hand so we can control keys
        cls._soledad = initialize_soledad(
            cls.email,
            cls.gnupg_home,
            cls.tempdir)

        # now we're passing the mailbox name, so we
        # should get this into a partial or something.
        # cls.sm = SoledadMailbox("mailbox", soledad=cls._soledad)
        # XXX REFACTOR --- self.server (in setUp) is initializing
        # a SoledadBackedAccount

    @classmethod
    def tearDownClass(cls):
        """
        TestCase teardown method.

        Restores the old path and home environment variables.
        Removes the temporal dir created for tests.
        """
        cls._soledad.close()

        os.environ["PATH"] = cls.old_path
        os.environ["HOME"] = cls.old_home
        # safety check
        assert cls.tempdir.startswith('/tmp/leap_tests-')
        shutil.rmtree(cls.tempdir)

    def setUp(self):
        """
        Setup method for each test.

        Initializes and run a LEAP IMAP4 Server,
        but passing the same Soledad instance (it's costly to initialize),
        so we have to be sure to restore state across tests.
        """
        UUID = 'deadbeef',
        USERID = TEST_USER
        memstore = MemoryStore()

        d = defer.Deferred()
        self.server = LeapIMAPServer(
            uuid=UUID, userid=USERID,
            contextFactory=self.serverCTX,
            # XXX do we really need this??
            soledad=self._soledad)

        self.client = SimpleClient(d, contextFactory=self.clientCTX)
        self.connected = d

        # XXX REVIEW-ME.
        # We're adding theAccount here to server
        # but it was also passed to initialization
        # as it was passed to realm.
        # I THINK we ONLY need to do it at one place now.

        theAccount = SoledadBackedAccount(
            USERID,
            soledad=self._soledad,
            memstore=memstore)
        LeapIMAPServer.theAccount = theAccount

        # in case we get something from previous tests...
        for mb in self.server.theAccount.mailboxes:
            self.server.theAccount.delete(mb)

        # email parser
        self.parser = parser.Parser()

    def tearDown(self):
        """
        tearDown method called after each test.

        Deletes all documents in the Index, and deletes
        instances of server and client.
        """
        self.delete_all_docs()
        acct = self.server.theAccount
        for mb in acct.mailboxes:
            acct.delete(mb)

        # FIXME add again
        # for subs in acct.subscriptions:
            # acct.unsubscribe(subs)

        del self.server
        del self.client
        del self.connected

    def populateMessages(self):
        """
        Populates soledad instance with several simple messages
        """
        # XXX we should encapsulate this thru SoledadBackedAccount
        # instead.

        # XXX we also should put this in a mailbox!

        self._soledad.messages.add_msg('', uid=1, subject="test1")
        self._soledad.messages.add_msg('', uid=2, subject="test2")
        self._soledad.messages.add_msg('', uid=3, subject="test3")
        # XXX should change Flags too
        self._soledad.messages.add_msg('', uid=4, subject="test4")

    def delete_all_docs(self):
        """
        Deletes all the docs in the testing instance of the
        SoledadBackedAccount.
        """
        self.server.theAccount.deleteAllMessages(
            iknowhatiamdoing=True)

    def _cbStopClient(self, ignore):
        self.client.transport.loseConnection()

    def _ebGeneral(self, failure):
        self.client.transport.loseConnection()
        self.server.transport.loseConnection()
        # can we do something similar?
        # I guess this was ok with trial, but not in noseland...
        #log.err(failure, "Problem with %r" % (self.function,))
        raise failure.value
        #failure.trap(Exception)

    def loopback(self):
        return loopback.loopbackAsync(self.server, self.client)


#
# TestCases
#

class MessageCollectionTestCase(IMAP4HelperMixin, unittest.TestCase):

    """
    Tests for the MessageCollection class
    """
    count = 0

    def setUp(self):
        """
        setUp method for each test
        We override mixin method since we are only testing
        MessageCollection interface in this particular TestCase
        """
        memstore = MemoryStore()
        self.messages = MessageCollection("testmbox%s" % (self.count,),
                                          self._soledad, memstore=memstore)
        MessageCollectionTestCase.count += 1

    def tearDown(self):
        """
        tearDown method for each test
        """
        del self.messages

    def testEmptyMessage(self):
        """
        Test empty message and collection
        """
        em = self.messages._get_empty_doc()
        self.assertEqual(
            em,
            {
                "chash": '',
                "deleted": False,
                "flags": [],
                "mbox": "inbox",
                "seen": False,
                "multi": False,
                "size": 0,
                "type": "flags",
                "uid": 1,
            })
        self.assertEqual(self.messages.count(), 0)

    def testMultipleAdd(self):
        """
        Add multiple messages
        """
        mc = self.messages
        self.assertEqual(self.messages.count(), 0)

        def add_first():
            d = defer.gatherResults([
                mc.add_msg('Stuff 1', uid=1, subject="test1"),
                mc.add_msg('Stuff 2', uid=2, subject="test2"),
                mc.add_msg('Stuff 3', uid=3, subject="test3"),
                mc.add_msg('Stuff 4', uid=4, subject="test4")])
            return d

        def add_second(result):
            d = defer.gatherResults([
                mc.add_msg('Stuff 5', uid=5, subject="test5"),
                mc.add_msg('Stuff 6', uid=6, subject="test6"),
                mc.add_msg('Stuff 7', uid=7, subject="test7")])
            return d

        def check_second(result):
            return self.assertEqual(mc.count(), 7)

        d1 = add_first()
        d1.addCallback(add_second)
        d1.addCallback(check_second)

    @skip("needs update!")
    def testRecentCount(self):
        """
        Test the recent count
        """
        mc = self.messages
        countrecent = mc.count_recent
        eq = self.assertEqual

        self.assertEqual(countrecent(), 0)

        d = mc.add_msg('Stuff', uid=1, subject="test1")
        # For the semantics defined in the RFC, we auto-add the
        # recent flag by default.

        def add2(_):
            return mc.add_msg('Stuff', subject="test2", uid=2,
                              flags=('\\Deleted',))

        def add3(_):
            return mc.add_msg('Stuff', subject="test3", uid=3,
                              flags=('\\Recent',))

        def add4(_):
            return mc.add_msg('Stuff', subject="test4", uid=4,
                              flags=('\\Deleted', '\\Recent'))

        d.addCallback(lambda r: eq(countrecent(), 1))
        d.addCallback(add2)
        d.addCallback(lambda r: eq(countrecent(), 2))
        d.addCallback(add3)
        d.addCallback(lambda r: eq(countrecent(), 3))
        d.addCallback(add4)
        d.addCallback(lambda r: eq(countrecent(), 4))

    def testFilterByMailbox(self):
        """
        Test that queries filter by selected mailbox
        """
        mc = self.messages
        self.assertEqual(self.messages.count(), 0)

        def add_1():
            d1 = mc.add_msg('msg 1', uid=1, subject="test1")
            d2 = mc.add_msg('msg 2', uid=2, subject="test2")
            d3 = mc.add_msg('msg 3', uid=3, subject="test3")
            d = defer.gatherResults([d1, d2, d3])
            return d

        add_1().addCallback(lambda ignored: self.assertEqual(
                            mc.count(), 3))

        # XXX this has to be redone to fit memstore ------------#
        #newmsg = mc._get_empty_doc()
        #newmsg['mailbox'] = "mailbox/foo"
        #mc._soledad.create_doc(newmsg)
        #self.assertEqual(mc.count(), 3)
        #self.assertEqual(
            #len(mc._soledad.get_from_index(mc.TYPE_IDX, "flags")), 4)


class LeapIMAP4ServerTestCase(IMAP4HelperMixin, unittest.TestCase):
    # TODO this currently will use a memory-only store.
    # create a different one for testing soledad sync.

    """
    Tests for the generic behavior of the LeapIMAP4Server
    which, right now, it's just implemented in this test file as
    LeapIMAPServer. We will move the implementation, together with
    authentication bits, to leap.mail.imap.server so it can be instantiated
    from the tac file.

    Right now this TestCase tries to mimmick as close as possible the
    organization from the twisted.mail.imap tests so we can achieve
    a complete implementation. The order in which they appear reflect
    the intended order of implementation.
    """

    #
    # mailboxes operations
    #

    @deferred(timeout=None)
    def testCreate(self):
        """
        Test whether we can create mailboxes
        """
        succeed = ('testbox', 'test/box', 'test/', 'test/box/box', 'foobox')
        fail = ('testbox', 'test/box')

        def cb():
            self.result.append(1)

        def eb(failure):
            self.result.append(0)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def create():
            for name in succeed + fail:
                d = self.client.create(name)
                d.addCallback(strip(cb)).addErrback(eb)
            d.addCallbacks(self._cbStopClient, self._ebGeneral)

        self.result = []
        d1 = self.connected.addCallback(strip(login)).addCallback(
            strip(create))
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestCreate, succeed, fail)

    def _cbTestCreate(self, ignored, succeed, fail):
        self.assertEqual(self.result, [1] * len(succeed) + [0] * len(fail))

        mbox = LeapIMAPServer.theAccount.mailboxes
        answers = ['foobox', 'testbox', 'test/box', 'test', 'test/box/box']
        mbox.sort()
        answers.sort()
        self.assertEqual(mbox, [a for a in answers])

    @deferred(timeout=None)
    def testDelete(self):
        """
        Test whether we can delete mailboxes
        """
        LeapIMAPServer.theAccount.addMailbox('delete/me')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def delete():
            return self.client.delete('delete/me')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(delete), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(
            lambda _: self.assertEqual(
                LeapIMAPServer.theAccount.mailboxes, []))
        return d

    def testIllegalInboxDelete(self):
        """
        Test what happens if we try to delete the user Inbox.
        We expect that operation to fail.
        """
        self.stashed = None

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def delete():
            return self.client.delete('inbox')

        def stash(result):
            self.stashed = result

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(delete), self._ebGeneral)
        d1.addBoth(stash)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.failUnless(isinstance(self.stashed,
                                                           failure.Failure)))
        return d

    @deferred(timeout=None)
    def testNonExistentDelete(self):
        """
        Test what happens if we try to delete a non-existent mailbox.
        We expect an error raised stating 'No such mailbox'
        """
        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def delete():
            return self.client.delete('delete/me')
            self.failure = failure

        def deleteFailed(failure):
            self.failure = failure

        self.failure = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(delete)).addErrback(deleteFailed)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.assertTrue(
            str(self.failure.value).startswith('No such mailbox')))
        return d

    @deferred(timeout=None)
    def testIllegalDelete(self):
        """
        Try deleting a mailbox with sub-folders, and \NoSelect flag set.
        An exception is expected

        Obs: this test will fail if SoledadMailbox returns hardcoded flags.
        """
        LeapIMAPServer.theAccount.addMailbox('delete')
        to_delete = LeapIMAPServer.theAccount.getMailbox('delete')
        to_delete.setFlags((r'\Noselect',))
        to_delete.getFlags()
        LeapIMAPServer.theAccount.addMailbox('delete/me')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def delete():
            return self.client.delete('delete')

        def deleteFailed(failure):
            self.failure = failure

        self.failure = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(delete)).addErrback(deleteFailed)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        expected = ("Hierarchically inferior mailboxes exist "
                    "and \\Noselect is set")
        d.addCallback(lambda _:
                      self.assertEqual(str(self.failure.value), expected))
        return d

    @deferred(timeout=None)
    def testRename(self):
        """
        Test whether we can rename a mailbox
        """
        LeapIMAPServer.theAccount.addMailbox('oldmbox')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(
                          LeapIMAPServer.theAccount.mailboxes,
                          ['newname']))
        return d

    @deferred(timeout=None)
    def testIllegalInboxRename(self):
        """
        Try to rename inbox. We expect it to fail. Then it would be not
        an inbox anymore, would it?
        """
        self.stashed = None

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def rename():
            return self.client.rename('inbox', 'frotz')

        def stash(stuff):
            self.stashed = stuff

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addBoth(stash)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.failUnless(isinstance(
                          self.stashed, failure.Failure)))
        return d

    @deferred(timeout=None)
    def testHierarchicalRename(self):
        """
        Try to rename hierarchical mailboxes
        """
        LeapIMAPServer.theAccount.create('oldmbox/m1')
        LeapIMAPServer.theAccount.create('oldmbox/m2')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestHierarchicalRename)

    def _cbTestHierarchicalRename(self, ignored):
        mboxes = LeapIMAPServer.theAccount.mailboxes
        expected = ['newname', 'newname/m1', 'newname/m2']
        mboxes.sort()
        self.assertEqual(mboxes, [s for s in expected])

    @deferred(timeout=None)
    def testSubscribe(self):
        """
        Test whether we can mark a mailbox as subscribed to
        """
        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def subscribe():
            return self.client.subscribe('this/mbox')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(subscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(
                          LeapIMAPServer.theAccount.subscriptions,
                          ['this/mbox']))
        return d

    @deferred(timeout=None)
    def testUnsubscribe(self):
        """
        Test whether we can unsubscribe from a set of mailboxes
        """
        LeapIMAPServer.theAccount.subscribe('this/mbox')
        LeapIMAPServer.theAccount.subscribe('that/mbox')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def unsubscribe():
            return self.client.unsubscribe('this/mbox')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(unsubscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(
                          LeapIMAPServer.theAccount.subscriptions,
                          ['that/mbox']))
        return d

    @deferred(timeout=None)
    def testSelect(self):
        """
        Try to select a mailbox
        """
        self.server.theAccount.addMailbox('TESTMAILBOX-SELECT', creation_ts=42)
        self.selectedArgs = None

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            def selected(args):
                self.selectedArgs = args
                self._cbStopClient(None)
            d = self.client.select('TESTMAILBOX-SELECT')
            d.addCallback(selected)
            return d

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(select))
        d1.addErrback(self._ebGeneral)

        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(self._cbTestSelect)

    def _cbTestSelect(self, ignored):
        mbox = LeapIMAPServer.theAccount.getMailbox('TESTMAILBOX-SELECT')
        self.assertEqual(self.server.mbox.messages.mbox, mbox.messages.mbox)
        self.assertEqual(self.selectedArgs, {
            'EXISTS': 0, 'RECENT': 0, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': True
        })

    #
    # capabilities
    #

    @deferred(timeout=None)
    def testCapability(self):
        caps = {}

        def getCaps():
            def gotCaps(c):
                caps.update(c)
                self.server.transport.loseConnection()
            return self.client.getCapabilities().addCallback(gotCaps)
        d1 = self.connected.addCallback(
            strip(getCaps)).addErrback(self._ebGeneral)
        d = defer.gatherResults([self.loopback(), d1])
        expected = {'IMAP4rev1': None, 'NAMESPACE': None, 'IDLE': None}

        return d.addCallback(lambda _: self.assertEqual(expected, caps))

    @deferred(timeout=None)
    def testCapabilityWithAuth(self):
        caps = {}
        self.server.challengers[
            'CRAM-MD5'] = cred.credentials.CramMD5Credentials

        def getCaps():
            def gotCaps(c):
                caps.update(c)
                self.server.transport.loseConnection()
            return self.client.getCapabilities().addCallback(gotCaps)
        d1 = self.connected.addCallback(
            strip(getCaps)).addErrback(self._ebGeneral)

        d = defer.gatherResults([self.loopback(), d1])

        expCap = {'IMAP4rev1': None, 'NAMESPACE': None,
                  'IDLE': None, 'AUTH': ['CRAM-MD5']}

        return d.addCallback(lambda _: self.assertEqual(expCap, caps))

    #
    # authentication
    #

    @deferred(timeout=None)
    def testLogout(self):
        """
        Test log out
        """
        self.loggedOut = 0

        def logout():
            def setLoggedOut():
                self.loggedOut = 1
            self.client.logout().addCallback(strip(setLoggedOut))
        self.connected.addCallback(strip(logout)).addErrback(self._ebGeneral)
        d = self.loopback()
        return d.addCallback(lambda _: self.assertEqual(self.loggedOut, 1))

    @deferred(timeout=None)
    def testNoop(self):
        """
        Test noop command
        """
        self.responses = None

        def noop():
            def setResponses(responses):
                self.responses = responses
                self.server.transport.loseConnection()
            self.client.noop().addCallback(setResponses)
        self.connected.addCallback(strip(noop)).addErrback(self._ebGeneral)
        d = self.loopback()
        return d.addCallback(lambda _: self.assertEqual(self.responses, []))

    @deferred(timeout=None)
    def testLogin(self):
        """
        Test login
        """
        def login():
            d = self.client.login(TEST_USER, TEST_PASSWD)
            d.addCallback(self._cbStopClient)
        d1 = self.connected.addCallback(
            strip(login)).addErrback(self._ebGeneral)
        d = defer.gatherResults([d1, self.loopback()])
        return d.addCallback(self._cbTestLogin)

    def _cbTestLogin(self, ignored):
        self.assertEqual(self.server.account, LeapIMAPServer.theAccount)
        self.assertEqual(self.server.state, 'auth')

    @deferred(timeout=None)
    def testFailedLogin(self):
        """
        Test bad login
        """
        def login():
            d = self.client.login("bad_user@leap.se", TEST_PASSWD)
            d.addBoth(self._cbStopClient)

        d1 = self.connected.addCallback(
            strip(login)).addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestFailedLogin)

    def _cbTestFailedLogin(self, ignored):
        self.assertEqual(self.server.state, 'unauth')
        self.assertEqual(self.server.account, None)

    @deferred(timeout=None)
    def testLoginRequiringQuoting(self):
        """
        Test login requiring quoting
        """
        self.server._userid = '{test}user@leap.se'
        self.server._password = '{test}password'

        def login():
            d = self.client.login('{test}user@leap.se', '{test}password')
            d.addBoth(self._cbStopClient)

        d1 = self.connected.addCallback(
            strip(login)).addErrback(self._ebGeneral)
        d = defer.gatherResults([self.loopback(), d1])
        return d.addCallback(self._cbTestLoginRequiringQuoting)

    def _cbTestLoginRequiringQuoting(self, ignored):
        self.assertEqual(self.server.account, LeapIMAPServer.theAccount)
        self.assertEqual(self.server.state, 'auth')

    #
    # Inspection
    #

    @deferred(timeout=None)
    def testNamespace(self):
        """
        Test retrieving namespace
        """
        self.namespaceArgs = None

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def namespace():
            def gotNamespace(args):
                self.namespaceArgs = args
                self._cbStopClient(None)
            return self.client.namespace().addCallback(gotNamespace)

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(namespace))
        d1.addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.assertEqual(self.namespaceArgs,
                                                 [[['', '/']], [], []]))
        return d

    @deferred(timeout=None)
    def testExamine(self):
        """
        L{IMAP4Client.examine} issues an I{EXAMINE} command to the server and
        returns a L{Deferred} which fires with a C{dict} with as many of the
        following keys as the server includes in its response: C{'FLAGS'},
        C{'EXISTS'}, C{'RECENT'}, C{'UNSEEN'}, C{'READ-WRITE'}, C{'READ-ONLY'},
        C{'UIDVALIDITY'}, and C{'PERMANENTFLAGS'}.

        Unfortunately the server doesn't generate all of these so it's hard to
        test the client's handling of them here.  See
        L{IMAP4ClientExamineTests} below.

        See U{RFC 3501<http://www.faqs.org/rfcs/rfc3501.html>}, section 6.3.2,
        for details.
        """
        self.server.theAccount.addMailbox('test-mailbox-e',
                                          creation_ts=42)

        self.examinedArgs = None

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def examine():
            def examined(args):
                self.examinedArgs = args
                self._cbStopClient(None)
            d = self.client.examine('test-mailbox-e')
            d.addCallback(examined)
            return d

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(examine))
        d1.addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestExamine)

    def _cbTestExamine(self, ignored):
        mbox = self.server.theAccount.getMailbox('test-mailbox-e')
        self.assertEqual(self.server.mbox.messages.mbox, mbox.messages.mbox)
        self.assertEqual(self.examinedArgs, {
            'EXISTS': 0, 'RECENT': 0, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': False})

    def _listSetup(self, f):
        LeapIMAPServer.theAccount.addMailbox('root/subthingl',
                                             creation_ts=42)
        LeapIMAPServer.theAccount.addMailbox('root/another-thing',
                                             creation_ts=42)
        LeapIMAPServer.theAccount.addMailbox('non-root/subthing',
                                             creation_ts=42)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def listed(answers):
            self.listed = answers

        self.listed = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(f), self._ebGeneral)
        d1.addCallbacks(listed, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(lambda _: self.listed)

    @deferred(timeout=None)
    def testList(self):
        """
        Test List command
        """
        def list():
            return self.client.list('root', '%')
        d = self._listSetup(list)
        d.addCallback(lambda listed: self.assertEqual(
            sortNest(listed),
            sortNest([
                (SoledadMailbox.INIT_FLAGS, "/", "root/subthingl"),
                (SoledadMailbox.INIT_FLAGS, "/", "root/another-thing")
            ])
        ))
        return d

    @deferred(timeout=None)
    def testLSub(self):
        """
        Test LSub command
        """
        LeapIMAPServer.theAccount.subscribe('root/subthingl2')

        def lsub():
            return self.client.lsub('root', '%')
        d = self._listSetup(lsub)
        d.addCallback(self.assertEqual,
                      [(SoledadMailbox.INIT_FLAGS, "/", "root/subthingl2")])
        return d

    @deferred(timeout=None)
    def testStatus(self):
        """
        Test Status command
        """
        LeapIMAPServer.theAccount.addMailbox('root/subthings')
        # XXX FIXME ---- should populate this a little bit,
        # with unseen etc...

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def status():
            return self.client.status(
                'root/subthings', 'MESSAGES', 'UIDNEXT', 'UNSEEN')

        def statused(result):
            self.statused = result

        self.statused = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(status), self._ebGeneral)
        d1.addCallbacks(statused, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.assertEqual(
            self.statused,
            {'MESSAGES': 0, 'UIDNEXT': '1', 'UNSEEN': 0}
        ))
        return d

    @deferred(timeout=None)
    def testFailedStatus(self):
        """
        Test failed status command with a non-existent mailbox
        """
        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def status():
            return self.client.status(
                'root/nonexistent', 'MESSAGES', 'UIDNEXT', 'UNSEEN')

        def statused(result):
            self.statused = result

        def failed(failure):
            self.failure = failure

        self.statused = self.failure = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(status), self._ebGeneral)
        d1.addCallbacks(statused, failed)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(
            self._cbTestFailedStatus)

    def _cbTestFailedStatus(self, ignored):
        self.assertEqual(
            self.statused, None
        )
        self.assertEqual(
            self.failure.value.args,
            ('Could not open mailbox',)
        )

    #
    # messages
    #

    @deferred(timeout=None)
    def testFullAppend(self):
        """
        Test appending a full message to the mailbox
        """
        infile = util.sibpath(__file__, 'rfc822.message')
        message = open(infile)
        LeapIMAPServer.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def append():
            return self.client.append(
                'root/subthing',
                message,
                ('\\SEEN', '\\DELETED'),
                'Tue, 17 Jun 2003 11:22:16 -0600 (MDT)',
            )

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(append), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestFullAppend, infile)

    def _cbTestFullAppend(self, ignored, infile):
        mb = LeapIMAPServer.theAccount.getMailbox('root/subthing')
        self.assertEqual(1, len(mb.messages))

        msg = mb.messages.get_msg_by_uid(1)
        self.assertEqual(
            set(('\\Recent', '\\SEEN', '\\DELETED')),
            set(msg.getFlags()))

        self.assertEqual(
            'Tue, 17 Jun 2003 11:22:16 -0600 (MDT)',
            msg.getInternalDate())

        parsed = self.parser.parse(open(infile))
        body = parsed.get_payload()
        headers = dict(parsed.items())
        self.assertEqual(
            body,
            msg.getBodyFile().read())
        gotheaders = msg.getHeaders(True)

        self.assertItemsEqual(
            headers, gotheaders)

    @deferred(timeout=None)
    def testPartialAppend(self):
        """
        Test partially appending a message to the mailbox
        """
        infile = util.sibpath(__file__, 'rfc822.message')
        LeapIMAPServer.theAccount.addMailbox('PARTIAL/SUBTHING')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def append():
            message = file(infile)
            return self.client.sendCommand(
                imap4.Command(
                    'APPEND',
                    'PARTIAL/SUBTHING (\\SEEN) "Right now" '
                    '{%d}' % os.path.getsize(infile),
                    (), self.client._IMAP4Client__cbContinueAppend, message
                )
            )
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(append), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(
            self._cbTestPartialAppend, infile)

    def _cbTestPartialAppend(self, ignored, infile):
        mb = LeapIMAPServer.theAccount.getMailbox('PARTIAL/SUBTHING')
        self.assertEqual(1, len(mb.messages))
        msg = mb.messages.get_msg_by_uid(1)
        self.assertEqual(
            set(('\\SEEN', '\\Recent')),
            set(msg.getFlags())
        )
        parsed = self.parser.parse(open(infile))
        body = parsed.get_payload()
        self.assertEqual(
            body,
            msg.getBodyFile().read())

    @deferred(timeout=None)
    def testCheck(self):
        """
        Test check command
        """
        LeapIMAPServer.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            return self.client.select('root/subthing')

        def check():
            return self.client.check()

        d = self.connected.addCallback(strip(login))
        d.addCallbacks(strip(select), self._ebGeneral)
        d.addCallbacks(strip(check), self._ebGeneral)
        d.addCallbacks(self._cbStopClient, self._ebGeneral)
        return self.loopback()

        # Okay, that was fun

    @deferred(timeout=5)
    def testClose(self):
        """
        Test closing the mailbox. We expect to get deleted all messages flagged
        as such.
        """
        name = 'mailbox-close'
        self.server.theAccount.addMailbox(name)

        m = LeapIMAPServer.theAccount.getMailbox(name)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            return self.client.select(name)

        def add_messages():
            d1 = m.messages.add_msg(
                'test 1', uid=1, subject="Message 1",
                flags=('\\Deleted', 'AnotherFlag'))
            d2 = m.messages.add_msg(
                'test 2', uid=2, subject="Message 2",
                flags=('AnotherFlag',))
            d3 = m.messages.add_msg(
                'test 3', uid=3, subject="Message 3",
                flags=('\\Deleted',))
            d = defer.gatherResults([d1, d2, d3])
            return d

        def close():
            return self.client.close()

        d = self.connected.addCallback(strip(login))
        d.addCallbacks(strip(select), self._ebGeneral)
        d.addCallbacks(strip(add_messages), self._ebGeneral)
        d.addCallbacks(strip(close), self._ebGeneral)
        d.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d, d2]).addCallback(self._cbTestClose, m)

    def _cbTestClose(self, ignored, m):
        self.assertEqual(len(m.messages), 1)

        msg = m.messages.get_msg_by_uid(2)
        self.assertFalse(msg is None)
        self.assertEqual(
            msg._hdoc.content['subject'],
            'Message 2')
        self.failUnless(m.closed)

    @deferred(timeout=5)
    def testExpunge(self):
        """
        Test expunge command
        """
        name = 'mailbox-expunge'
        self.server.theAccount.addMailbox(name)
        m = LeapIMAPServer.theAccount.getMailbox(name)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            return self.client.select('mailbox-expunge')

        def add_messages():
            d1 = m.messages.add_msg(
                'test 1', uid=1, subject="Message 1",
                flags=('\\Deleted', 'AnotherFlag'))
            d2 = m.messages.add_msg(
                'test 2', uid=2, subject="Message 2",
                flags=('AnotherFlag',))
            d3 = m.messages.add_msg(
                'test 3', uid=3, subject="Message 3",
                flags=('\\Deleted',))
            d = defer.gatherResults([d1, d2, d3])
            return d

        def expunge():
            return self.client.expunge()

        def expunged(results):
            self.failIf(self.server.mbox is None)
            self.results = results

        self.results = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(select), self._ebGeneral)
        d1.addCallbacks(strip(add_messages), self._ebGeneral)
        d1.addCallbacks(strip(expunge), self._ebGeneral)
        d1.addCallbacks(expunged, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestExpunge, m)

    def _cbTestExpunge(self, ignored, m):
        # we only left 1 mssage with no deleted flag
        self.assertEqual(len(m.messages), 1)

        msg = m.messages.get_msg_by_uid(2)
        self.assertEqual(
            msg._hdoc.content['subject'],
            'Message 2')
        # the uids of the deleted messages
        self.assertItemsEqual(self.results, [1, 3])


class StoreAndFetchTestCase(unittest.TestCase, IMAP4HelperMixin):
    """
    Several tests to check that the internal storage representation
    is able to render the message structures as we expect them.
    """
    # TODO get rid of the fucking sleeps with a proper defer
    # management.

    def setUp(self):
        IMAP4HelperMixin.setUp(self)
        MBOX_NAME = "multipart/SIGNED"
        self.received_messages = self.received_uid = None
        self.result = None

        self.server.state = 'select'

        infile = util.sibpath(__file__, 'rfc822.multi-signed.message')
        raw = open(infile).read()

        self.server.theAccount.addMailbox(MBOX_NAME)
        mbox = self.server.theAccount.getMailbox(MBOX_NAME)
        time.sleep(1)
        self.server.mbox = mbox
        self.server.mbox.messages.add_msg(raw, uid=1)
        time.sleep(1)

    def addListener(self, x):
        pass

    def removeListener(self, x):
        pass

    def _fetchWork(self, uids):

        def result(R):
            self.result = R

        self.connected.addCallback(
            lambda _: self.function(
                uids, uid=1)  # do NOT use seq numbers!
            ).addCallback(result).addCallback(
            self._cbStopClient).addErrback(self._ebGeneral)

        d = loopback.loopbackTCP(self.server, self.client, noisy=False)
        d.addCallback(lambda x: self.assertEqual(self.result, self.expected))
        return d

    @deferred(timeout=None)
    def testMultiBody(self):
        """
        Test that a multipart signed message is retrieved the same
        as we stored it.
        """
        time.sleep(1)
        self.function = self.client.fetchBody
        messages = '1'

        # XXX review. This probably should give everything?

        self.expected = {1: {
            'RFC822.TEXT': 'This is an example of a signed message,\n'
                           'with attachments.\n\n\n--=20\n'
                           'Nihil sine chao! =E2=88=B4\n',
            'UID': '1'}}
        print "test multi: fetch uid", messages
        return self._fetchWork(messages)


class IMAP4ServerSearchTestCase(IMAP4HelperMixin, unittest.TestCase):

    """
    Tests for the behavior of the search_* functions in L{imap5.IMAP4Server}.
    """
    # XXX coming soon to your screens!
    pass


def tearDownModule():
    """
    Tear down functions for module level
    """
    stop_reactor()
