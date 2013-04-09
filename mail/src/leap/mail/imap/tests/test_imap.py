#-*- encoding: utf-8 -*-
"""
leap/email/imap/tests/test_imap.py
----------------------------------
Test case for leap.email.imap.server

@authors: Kali Kaneko, <kali@leap.se>
@license: GPLv3, see included LICENSE file
@copyright: © 2013 Kali Kaneko, see COPYLEFT file
"""

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import codecs
import locale
import os
import types
import tempfile
import shutil


from zope.interface import implements

from twisted.mail.imap4 import MessageSet
from twisted.mail import imap4
from twisted.protocols import loopback
from twisted.internet import defer
from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import interfaces
from twisted.internet.task import Clock
from twisted.trial import unittest
from twisted.python import util, log
from twisted.python import failure

from twisted import cred
import twisted.cred.error
import twisted.cred.checkers
import twisted.cred.credentials
import twisted.cred.portal

from twisted.test.proto_helpers import StringTransport, StringTransportWithDisconnection


import u1db

from leap.common.testing.basetest import BaseLeapTest
from leap.mail.imap.server import SoledadMailbox
from leap.mail.imap.tests import PUBLIC_KEY
from leap.mail.imap.tests import PRIVATE_KEY

from leap.soledad import Soledad
from leap.soledad.util import GPGWrapper
from leap.soledad.backends.leap_backend import LeapDocument


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
    initializes soledad by hand
    """
    _soledad = Soledad(email, gnupg_home=gnupg_home,
                            initialize=False,
                            prefix=tempdir)
    _soledad._init_dirs()
    _soledad._gpg = GPGWrapper(gnupghome=gnupg_home)
    _soledad._gpg.import_keys(PUBLIC_KEY)
    _soledad._gpg.import_keys(PRIVATE_KEY)
    _soledad._load_openpgp_keypair()
    if not _soledad._has_secret():
        _soledad._gen_secret()
    _soledad._load_secret()
    _soledad._init_db()
    return _soledad


##########################################
# account, simpleserver
##########################################


class SoledadBackedAccount(imap4.MemoryAccount):
    #mailboxFactory = SimpleMailbox
    mailboxFactory = SoledadMailbox
    soledadInstance = None

    # XXX should reimplement IAccount -> SoledadAccount
    # and receive the soledad instance on the constructor.
    # SoledadMailbox should allow to filter by mailbox name
    # _soledad db should include mailbox field
    # and a document with "INDEX" info (mailboxes / subscriptions)

    def _emptyMailbox(self, name, id):
        return self.mailboxFactory(self.soledadInstance)

    def select(self, name, rw=1):
        # XXX rethink this.
        # Need to be classmethods...
        mbox = imap4.MemoryAccount.select(self, name)
        if mbox is not None:
            mbox.rw = rw
        return mbox


class SimpleLEAPServer(imap4.IMAP4Server):
    def __init__(self, *args, **kw):
        imap4.IMAP4Server.__init__(self, *args, **kw)
        realm = TestRealm()
        realm.theAccount = SoledadBackedAccount('testuser')
        # XXX soledadInstance here?

        portal = cred.portal.Portal(realm)
        c = cred.checkers.InMemoryUsernamePasswordDatabaseDontUse()
        self.checker = c
        self.portal = portal
        portal.registerChecker(c)
        self.timeoutTest = False

    def lineReceived(self, line):
        if self.timeoutTest:
            #Do not send a respones
            return

        imap4.IMAP4Server.lineReceived(self, line)

    _username = 'testuser'
    _password = 'password-test'

    def authenticateLogin(self, username, password):
        if username == self._username and password == self._password:
            return imap4.IAccount, self.theAccount, lambda: None
        raise cred.error.UnauthorizedLogin()


class TestRealm:
    theAccount = None

    def requestAvatar(self, avatarId, mind, *interfaces):
        return imap4.IAccount, self.theAccount, lambda: None

######################
# Test LEAP Server
######################


class SimpleClient(imap4.IMAP4Client):

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

    serverCTX = None
    clientCTX = None

    @classmethod
    def setUpClass(cls):
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
        #cls.db1_file = "%s/db1.u1db" % cls.tempdir
        #cls.db2_file = "%s/db2.u1db" % cls.tempdir
        # open test dbs
        #cls._db1 = u1db.open(cls.db1_file, create=True,
                              #document_factory=LeapDocument)
        #cls._db2 = u1db.open(cls.db2_file, create=True,
                              #document_factory=LeapDocument)

        # initialize soledad by hand so we can control keys
        cls._soledad = initialize_soledad(
            cls.email,
            cls.gnupg_home,
            cls.tempdir)

        cls.sm = SoledadMailbox(soledad=cls._soledad)

    @classmethod
    def tearDownClass(cls):
        #cls._db1.close()
        #cls._db2.close()
        cls._soledad.close()

        os.environ["PATH"] = cls.old_path
        os.environ["HOME"] = cls.old_home
        # safety check
        assert cls.tempdir.startswith('/tmp/leap_tests-')
        shutil.rmtree(cls.tempdir)

    def setUp(self):
        d = defer.Deferred()
        self.server = SimpleLEAPServer(contextFactory=self.serverCTX)
        self.client = SimpleClient(d, contextFactory=self.clientCTX)
        self.connected = d

        theAccount = SoledadBackedAccount('testuser')
        theAccount.soledadInstance = self._soledad

        # XXX used for something???
        #theAccount.mboxType = SoledadMailbox
        SimpleLEAPServer.theAccount = theAccount

    def tearDown(self):
        self.delete_all_docs()
        del self.server
        del self.client
        del self.connected

    def populateMessages(self):
        self._soledad.messages.add_msg(subject="test1")
        self._soledad.messages.add_msg(subject="test2")
        self._soledad.messages.add_msg(subject="test3")
        # XXX should change Flags too
        self._soledad.messages.add_msg(subject="test4")

    def delete_all_docs(self):
        self.server.theAccount.messages.deleteAllDocs()

    def _cbStopClient(self, ignore):
        self.client.transport.loseConnection()

    def _ebGeneral(self, failure):
        self.client.transport.loseConnection()
        self.server.transport.loseConnection()
        log.err(failure, "Problem with %r" % (self.function,))

    def loopback(self):
        return loopback.loopbackAsync(self.server, self.client)


class IMAP4ServerTestCase(IMAP4HelperMixin, unittest.TestCase):

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

    def testLogout(self):
        self.loggedOut = 0

        def logout():
            def setLoggedOut():
                self.loggedOut = 1
            self.client.logout().addCallback(strip(setLoggedOut))
        self.connected.addCallback(strip(logout)).addErrback(self._ebGeneral)
        d = self.loopback()
        return d.addCallback(lambda _: self.assertEqual(self.loggedOut, 1))

    def testNoop(self):
        self.responses = None

        def noop():
            def setResponses(responses):
                self.responses = responses
                self.server.transport.loseConnection()
            self.client.noop().addCallback(setResponses)
        self.connected.addCallback(strip(noop)).addErrback(self._ebGeneral)
        d = self.loopback()
        return d.addCallback(lambda _: self.assertEqual(self.responses, []))

    def testLogin(self):
        def login():
            d = self.client.login('testuser', 'password-test')
            d.addCallback(self._cbStopClient)
        d1 = self.connected.addCallback(strip(login)).addErrback(self._ebGeneral)
        d = defer.gatherResults([d1, self.loopback()])
        return d.addCallback(self._cbTestLogin)

    def _cbTestLogin(self, ignored):
        self.assertEqual(self.server.account, SimpleLEAPServer.theAccount)
        self.assertEqual(self.server.state, 'auth')

    def testFailedLogin(self):
        def login():
            d = self.client.login('testuser', 'wrong-password')
            d.addBoth(self._cbStopClient)

        d1 = self.connected.addCallback(strip(login)).addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestFailedLogin)

    def _cbTestFailedLogin(self, ignored):
        self.assertEqual(self.server.account, None)
        self.assertEqual(self.server.state, 'unauth')


    def testLoginRequiringQuoting(self):
        self.server._username = '{test}user'
        self.server._password = '{test}password'

        def login():
            d = self.client.login('{test}user', '{test}password')
            d.addBoth(self._cbStopClient)

        d1 = self.connected.addCallback(strip(login)).addErrback(self._ebGeneral)
        d = defer.gatherResults([self.loopback(), d1])
        return d.addCallback(self._cbTestLoginRequiringQuoting)

    def _cbTestLoginRequiringQuoting(self, ignored):
        self.assertEqual(self.server.account, SimpleLEAPServer.theAccount)
        self.assertEqual(self.server.state, 'auth')


    def testNamespace(self):
        self.namespaceArgs = None
        def login():
            return self.client.login('testuser', 'password-test')
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

    def testSelect(self):
        SimpleLEAPServer.theAccount.addMailbox('test-mailbox')
        self.selectedArgs = None

        def login():
            return self.client.login('testuser', 'password-test')

        def select():
            def selected(args):
                self.selectedArgs = args
                self._cbStopClient(None)
            d = self.client.select('test-mailbox')
            d.addCallback(selected)
            return d

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(select))
        d1.addErrback(self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(self._cbTestSelect)

    def _cbTestSelect(self, ignored):
        mbox = SimpleLEAPServer.theAccount.mailboxes['TEST-MAILBOX']
        self.assertEqual(self.server.mbox, mbox)
        self.assertEqual(self.selectedArgs, {
            'EXISTS': 9, 'RECENT': 3, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': 1
        })

    def test_examine(self):
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
        SimpleLEAPServer.theAccount.addMailbox('test-mailbox')
        self.examinedArgs = None

        def login():
            return self.client.login('testuser', 'password-test')

        def examine():
            def examined(args):
                self.examinedArgs = args
                self._cbStopClient(None)
            d = self.client.examine('test-mailbox')
            d.addCallback(examined)
            return d

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(examine))
        d1.addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestExamine)

    def _cbTestExamine(self, ignored):
        mbox = SimpleLEAPServer.theAccount.mailboxes['TEST-MAILBOX']
        self.assertEqual(self.server.mbox, mbox)
        self.assertEqual(self.examinedArgs, {
            'EXISTS': 9, 'RECENT': 3, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': False})

    def testCreate(self):
        succeed = ('testbox', 'test/box', 'test/', 'test/box/box', 'INBOX')
        fail = ('testbox', 'test/box')

        def cb():
            self.result.append(1)

        def eb(failure):
            self.result.append(0)

        def login():
            return self.client.login('testuser', 'password-test')

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
        mbox = SimpleLEAPServer.theAccount.mailboxes.keys()
        answers = ['inbox', 'testbox', 'test/box', 'test', 'test/box/box']
        mbox.sort()
        answers.sort()
        self.assertEqual(mbox, [a.upper() for a in answers])

    def testDelete(self):
        SimpleLEAPServer.theAccount.addMailbox('delete/me')

        def login():
            return self.client.login('testuser', 'password-test')

        def delete():
            return self.client.delete('delete/me')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(delete), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(SimpleLEAPServer.theAccount.mailboxes.keys(), []))
        return d

    def testIllegalInboxDelete(self):
        self.stashed = None

        def login():
            return self.client.login('testuser', 'password-test')

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

    def testNonExistentDelete(self):

        def login():
            return self.client.login('testuser', 'password-test')

        def delete():
            return self.client.delete('delete/me')

        def deleteFailed(failure):
            self.failure = failure

        self.failure = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(delete)).addErrback(deleteFailed)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.assertEqual(str(self.failure.value),
                                                  'No such mailbox'))
        return d

    def testIllegalDelete(self):
        m = SoledadMailbox()
        m.flags = (r'\Noselect',)
        SimpleLEAPServer.theAccount.addMailbox('delete', m)
        SimpleLEAPServer.theAccount.addMailbox('delete/me')

        def login():
            return self.client.login('testuser', 'password-test')

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

    def testRename(self):
        SimpleLEAPServer.theAccount.addMailbox('oldmbox')

        def login():
            return self.client.login('testuser', 'password-test')

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(
                        SimpleLEAPServer.theAccount.mailboxes.keys(),
                        ['NEWNAME']))
        return d

    def testIllegalInboxRename(self):
        self.stashed = None

        def login():
            return self.client.login('testuser', 'password-test')

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

    def testHierarchicalRename(self):
        SimpleLEAPServer.theAccount.create('oldmbox/m1')
        SimpleLEAPServer.theAccount.create('oldmbox/m2')

        def login():
            return self.client.login('testuser', 'password-test')

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestHierarchicalRename)

    def _cbTestHierarchicalRename(self, ignored):
        mboxes = SimpleLEAPServer.theAccount.mailboxes.keys()
        expected = ['newname', 'newname/m1', 'newname/m2']
        mboxes.sort()
        self.assertEqual(mboxes, [s.upper() for s in expected])

    def testSubscribe(self):

        def login():
            return self.client.login('testuser', 'password-test')

        def subscribe():
            return self.client.subscribe('this/mbox')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(subscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(SimpleLEAPServer.theAccount.subscriptions,
                                        ['THIS/MBOX']))
        return d

    def testUnsubscribe(self):
        SimpleLEAPServer.theAccount.subscriptions = ['THIS/MBOX', 'THAT/MBOX']
        def login():
            return self.client.login('testuser', 'password-test')
        def unsubscribe():
            return self.client.unsubscribe('this/mbox')

        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(unsubscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.assertEqual(SimpleLEAPServer.theAccount.subscriptions,
                                        ['THAT/MBOX']))
        return d

    def _listSetup(self, f):
        SimpleLEAPServer.theAccount.addMailbox('root/subthing')
        SimpleLEAPServer.theAccount.addMailbox('root/another-thing')
        SimpleLEAPServer.theAccount.addMailbox('non-root/subthing')

        def login():
            return self.client.login('testuser', 'password-test')

        def listed(answers):
            self.listed = answers

        self.listed = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(f), self._ebGeneral)
        d1.addCallbacks(listed, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(lambda _: self.listed)

    def testList(self):
        def list():
            return self.client.list('root', '%')
        d = self._listSetup(list)
        d.addCallback(lambda listed: self.assertEqual(
            sortNest(listed),
            sortNest([
                (SoledadMailbox.flags, "/", "ROOT/SUBTHING"),
                (SoledadMailbox.flags, "/", "ROOT/ANOTHER-THING")
            ])
        ))
        return d

    def testLSub(self):
        SimpleLEAPServer.theAccount.subscribe('ROOT/SUBTHING')

        def lsub():
            return self.client.lsub('root', '%')
        d = self._listSetup(lsub)
        d.addCallback(self.assertEqual,
                      [(SoledadMailbox.flags, "/", "ROOT/SUBTHING")])
        return d

    def testStatus(self):
        SimpleLEAPServer.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login('testuser', 'password-test')

        def status():
            return self.client.status(
                'root/subthing', 'MESSAGES', 'UIDNEXT', 'UNSEEN')

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
            {'MESSAGES': 9, 'UIDNEXT': '10', 'UNSEEN': 4}
        ))
        return d

    def testFailedStatus(self):
        def login():
            return self.client.login('testuser', 'password-test')

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

    def testFullAppend(self):
        infile = util.sibpath(__file__, 'rfc822.message')
        message = open(infile)
        SimpleLEAPServer.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login('testuser', 'password-test')

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
        mb = SimpleLEAPServer.theAccount.mailboxes['ROOT/SUBTHING']
        self.assertEqual(1, len(mb.messages))
        self.assertEqual(
            (['\\SEEN', '\\DELETED'], 'Tue, 17 Jun 2003 11:22:16 -0600 (MDT)', 0),
            mb.messages[0][1:]
        )
        self.assertEqual(open(infile).read(), mb.messages[0][0].getvalue())

    def testPartialAppend(self):
        infile = util.sibpath(__file__, 'rfc822.message')
        message = open(infile)
        SimpleLEAPServer.theAccount.addMailbox('PARTIAL/SUBTHING')

        def login():
            return self.client.login('testuser', 'password-test')

        def append():
            message = file(infile)
            return self.client.sendCommand(
                imap4.Command(
                    'APPEND',
                    'PARTIAL/SUBTHING (\\SEEN) "Right now" {%d}' % os.path.getsize(infile),
                    (), self.client._IMAP4Client__cbContinueAppend, message
                )
            )
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(append), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestPartialAppend, infile)

    def _cbTestPartialAppend(self, ignored, infile):
        mb = SimpleLEAPServer.theAccount.mailboxes['PARTIAL/SUBTHING']
        self.assertEqual(1, len(mb.messages))
        self.assertEqual(
            (['\\SEEN'], 'Right now', 0),
            mb.messages[0][1:]
        )
        self.assertEqual(open(infile).read(), mb.messages[0][0].getvalue())

    def testCheck(self):
        SimpleLEAPServer.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login('testuser', 'password-test')

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

    def testClose(self):
        m = SoledadMailbox()
        m.messages = [
            ('Message 1', ('\\Deleted', 'AnotherFlag'), None, 0),
            ('Message 2', ('AnotherFlag',), None, 1),
            ('Message 3', ('\\Deleted',), None, 2),
        ]
        SimpleLEAPServer.theAccount.addMailbox('mailbox', m)

        def login():
            return self.client.login('testuser', 'password-test')

        def select():
            return self.client.select('mailbox')

        def close():
            return self.client.close()

        d = self.connected.addCallback(strip(login))
        d.addCallbacks(strip(select), self._ebGeneral)
        d.addCallbacks(strip(close), self._ebGeneral)
        d.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d, d2]).addCallback(self._cbTestClose, m)

    def _cbTestClose(self, ignored, m):
        self.assertEqual(len(m.messages), 1)
        self.assertEqual(m.messages[0],
            ('Message 2', ('AnotherFlag',), None, 1))
        self.failUnless(m.closed)

    def testExpunge(self):
        m = SoledadMailbox()
        m.messages = [
            ('Message 1', ('\\Deleted', 'AnotherFlag'), None, 0),
            ('Message 2', ('AnotherFlag',), None, 1),
            ('Message 3', ('\\Deleted',), None, 2),
        ]
        SimpleLEAPServer.theAccount.addMailbox('mailbox', m)

        def login():
            return self.client.login('testuser', 'password-test')

        def select():
            return self.client.select('mailbox')

        def expunge():
            return self.client.expunge()

        def expunged(results):
            self.failIf(self.server.mbox is None)
            self.results = results

        self.results = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallbacks(strip(select), self._ebGeneral)
        d1.addCallbacks(strip(expunge), self._ebGeneral)
        d1.addCallbacks(expunged, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestExpunge, m)

    def _cbTestExpunge(self, ignored, m):
        self.assertEqual(len(m.messages), 1)
        self.assertEqual(m.messages[0],
            ('Message 2', ('AnotherFlag',), None, 1))

        self.assertEqual(self.results, [0, 2])



class IMAP4ServerSearchTestCase(IMAP4HelperMixin, unittest.TestCase):
    """
    Tests for the behavior of the search_* functions in L{imap4.IMAP4Server}.
    """
    pass
