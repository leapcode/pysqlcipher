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
against our implementation of the IMAPAccount.

@authors: Kali Kaneko, <kali@leap.se>
XXX add authors from the original twisted tests.

@license: GPLv3, see included LICENSE file
"""
# XXX review license of the original tests!!!
import os
import string
import types


from twisted.mail import imap4
from twisted.internet import defer
from twisted.python import util
from twisted.python import failure

from twisted import cred

from leap.mail.imap.mailbox import IMAPMailbox
from leap.mail.imap.messages import CaseInsensitiveDict
from leap.mail.imap.tests.utils import IMAP4HelperMixin


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


class TestRealm:
    """
    A minimal auth realm for testing purposes only
    """
    theAccount = None

    def requestAvatar(self, avatarId, mind, *interfaces):
        return imap4.IAccount, self.theAccount, lambda: None

#
# TestCases
#

# DEBUG ---
# from twisted.internet.base import DelayedCall
# DelayedCall.debug = True


class LEAPIMAP4ServerTestCase(IMAP4HelperMixin):

    """
    Tests for the generic behavior of the LEAPIMAP4Server
    which, right now, it's just implemented in this test file as
    LEAPIMAPServer. We will move the implementation, together with
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

    def testCreate(self):
        """
        Test whether we can create mailboxes
        """
        succeed = ('testbox', 'test/box', 'test/', 'test/box/box', 'foobox')
        fail = ('testbox', 'test/box')
        acc = self.server.theAccount

        def cb():
            self.result.append(1)

        def eb(failure):
            self.result.append(0)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def create():
            create_deferreds = []
            for name in succeed + fail:
                d = self.client.create(name)
                d.addCallback(strip(cb)).addErrback(eb)
                create_deferreds.append(d)
            dd = defer.gatherResults(create_deferreds)
            dd.addCallbacks(self._cbStopClient, self._ebGeneral)
            return dd

        self.result = []
        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(create))
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2], consumeErrors=True)
        d.addCallback(lambda _: acc.account.list_all_mailbox_names())
        return d.addCallback(self._cbTestCreate, succeed, fail)

    def _cbTestCreate(self, mailboxes, succeed, fail):
        self.assertEqual(self.result, [1] * len(succeed) + [0] * len(fail))

        answers = ([u'INBOX', u'testbox', u'test/box', u'test',
                    u'test/box/box', 'foobox'])
        self.assertEqual(sorted(mailboxes), sorted([a for a in answers]))

    def testDelete(self):
        """
        Test whether we can delete mailboxes
        """
        def add_mailbox():
            return self.server.theAccount.addMailbox('test-delete/me')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def delete():
            return self.client.delete('test-delete/me')

        acc = self.server.theAccount.account

        d1 = self.connected.addCallback(add_mailbox)
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(delete), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: acc.list_all_mailbox_names())
        d.addCallback(lambda mboxes: self.assertEqual(
            mboxes, ['INBOX']))
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

    def testIllegalDelete(self):
        """
        Try deleting a mailbox with sub-folders, and \NoSelect flag set.
        An exception is expected.
        """
        acc = self.server.theAccount

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def create_mailboxes():
            d1 = acc.addMailbox('delete')
            d2 = acc.addMailbox('delete/me')
            d = defer.gatherResults([d1, d2])
            return d

        def get_noselect_mailbox(mboxes):
            mbox = mboxes[0]
            return mbox.setFlags((r'\Noselect',))

        def delete_mbox(ignored):
            return self.client.delete('delete')

        def deleteFailed(failure):
            self.failure = failure

        self.failure = None

        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(create_mailboxes))
        d1.addCallback(get_noselect_mailbox)

        d1.addCallback(delete_mbox).addErrback(deleteFailed)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        expected = ("Hierarchically inferior mailboxes exist "
                    "and \\Noselect is set")
        d.addCallback(lambda _:
                      self.assertTrue(self.failure is not None))
        d.addCallback(lambda _:
                      self.assertEqual(str(self.failure.value), expected))
        return d

    # FIXME --- this test sometimes FAILS (timing issue).
    # Some of the deferreds used in the rename op is not waiting for the
    # operations properly
    def testRename(self):
        """
        Test whether we can rename a mailbox
        """
        def create_mbox():
            return self.server.theAccount.addMailbox('oldmbox')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(create_mbox))
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _:
                      self.server.theAccount.account.list_all_mailbox_names())
        d.addCallback(lambda mboxes:
                      self.assertItemsEqual(mboxes, ['INBOX', 'newname']))
        return d

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

    def testHierarchicalRename(self):
        """
        Try to rename hierarchical mailboxes
        """
        acc = self.server.theAccount

        def add_mailboxes():
            return defer.gatherResults([
                acc.addMailbox('oldmbox/m1'),
                acc.addMailbox('oldmbox/m2')])

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def rename():
            return self.client.rename('oldmbox', 'newname')

        d1 = self.connected.addCallback(strip(add_mailboxes))
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(rename), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: acc.account.list_all_mailbox_names())
        return d.addCallback(self._cbTestHierarchicalRename)

    def _cbTestHierarchicalRename(self, mailboxes):
        expected = ['INBOX', 'newname/m1', 'newname/m2']
        self.assertEqual(sorted(mailboxes), sorted([s for s in expected]))

    def testSubscribe(self):
        """
        Test whether we can mark a mailbox as subscribed to
        """
        acc = self.server.theAccount

        def add_mailbox():
            return acc.addMailbox('this/mbox')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def subscribe():
            return self.client.subscribe('this/mbox')

        def get_subscriptions(ignored):
            return self.server.theAccount.getSubscriptions()

        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(subscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(get_subscriptions)
        d.addCallback(lambda subscriptions:
                      self.assertEqual(subscriptions,
                                       ['this/mbox']))
        return d

    def testUnsubscribe(self):
        """
        Test whether we can unsubscribe from a set of mailboxes
        """
        acc = self.server.theAccount

        def add_mailboxes():
            return defer.gatherResults([
                acc.addMailbox('this/mbox'),
                acc.addMailbox('that/mbox')])

        def dc1():
            return acc.subscribe('this/mbox')

        def dc2():
            return acc.subscribe('that/mbox')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def unsubscribe():
            return self.client.unsubscribe('this/mbox')

        def get_subscriptions(ignored):
            return acc.getSubscriptions()

        d1 = self.connected.addCallback(strip(add_mailboxes))
        d1.addCallback(strip(login))
        d1.addCallback(strip(dc1))
        d1.addCallback(strip(dc2))
        d1.addCallbacks(strip(unsubscribe), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(get_subscriptions)
        d.addCallback(lambda subscriptions:
                      self.assertEqual(subscriptions,
                                       ['that/mbox']))
        return d

    def testSelect(self):
        """
        Try to select a mailbox
        """
        mbox_name = "TESTMAILBOXSELECT"
        self.selectedArgs = None

        acc = self.server.theAccount

        def add_mailbox():
            return acc.addMailbox(mbox_name, creation_ts=42)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            def selected(args):
                self.selectedArgs = args
                self._cbStopClient(None)
            d = self.client.select(mbox_name)
            d.addCallback(selected)
            return d

        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallback(strip(select))
        # d1.addErrback(self._ebGeneral)

        d2 = self.loopback()

        d = defer.gatherResults([d1, d2])
        d.addCallback(self._cbTestSelect)
        return d

    def _cbTestSelect(self, ignored):
        self.assertTrue(self.selectedArgs is not None)

        self.assertEqual(self.selectedArgs, {
            'EXISTS': 0, 'RECENT': 0, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': True
        })

    #
    # capabilities
    #

    def testCapability(self):
        caps = {}

        def getCaps():
            def gotCaps(c):
                caps.update(c)
                self.server.transport.loseConnection()
            return self.client.getCapabilities().addCallback(gotCaps)

        d1 = self.connected
        d1.addCallback(
            strip(getCaps)).addErrback(self._ebGeneral)

        d = defer.gatherResults([self.loopback(), d1])
        expected = {'IMAP4rev1': None, 'NAMESPACE': None, 'LITERAL+': None,
                    'IDLE': None}
        d.addCallback(lambda _: self.assertEqual(expected, caps))
        return d

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
                  'IDLE': None, 'LITERAL+': None,
                  'AUTH': ['CRAM-MD5']}

        d.addCallback(lambda _: self.assertEqual(expCap, caps))
        return d

    #
    # authentication
    #

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
        self.assertEqual(self.server.state, 'auth')

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

    def testLoginRequiringQuoting(self):
        """
        Test login requiring quoting
        """
        self.server.checker.userid = '{test}user@leap.se'
        self.server.checker.password = '{test}password'

        def login():
            d = self.client.login('{test}user@leap.se', '{test}password')
            d.addBoth(self._cbStopClient)

        d1 = self.connected.addCallback(
            strip(login)).addErrback(self._ebGeneral)
        d = defer.gatherResults([self.loopback(), d1])
        return d.addCallback(self._cbTestLoginRequiringQuoting)

    def _cbTestLoginRequiringQuoting(self, ignored):
        self.assertEqual(self.server.state, 'auth')

    #
    # Inspection
    #

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
        # TODO implement the IMAP4ClientExamineTests testcase.
        mbox_name = "test_mailbox_e"
        acc = self.server.theAccount
        self.examinedArgs = None

        def add_mailbox():
            return acc.addMailbox(mbox_name, creation_ts=42)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def examine():
            def examined(args):
                self.examinedArgs = args
                self._cbStopClient(None)
            d = self.client.examine(mbox_name)
            d.addCallback(examined)
            return d

        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallback(strip(examine))
        d1.addErrback(self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        return d.addCallback(self._cbTestExamine)

    def _cbTestExamine(self, ignored):
        self.assertEqual(self.examinedArgs, {
            'EXISTS': 0, 'RECENT': 0, 'UIDVALIDITY': 42,
            'FLAGS': ('\\Seen', '\\Answered', '\\Flagged',
                      '\\Deleted', '\\Draft', '\\Recent', 'List'),
            'READ-WRITE': False})

    def _listSetup(self, f, f2=None):

        acc = self.server.theAccount

        def dc1():
            return acc.addMailbox('root_subthing', creation_ts=42)

        def dc2():
            return acc.addMailbox('root_another_thing', creation_ts=42)

        def dc3():
            return acc.addMailbox('non_root_subthing', creation_ts=42)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def listed(answers):
            self.listed = answers

        self.listed = None
        d1 = self.connected.addCallback(strip(login))
        d1.addCallback(strip(dc1))
        d1.addCallback(strip(dc2))
        d1.addCallback(strip(dc3))

        if f2 is not None:
            d1.addCallback(f2)

        d1.addCallbacks(strip(f), self._ebGeneral)
        d1.addCallbacks(listed, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d1, d2]).addCallback(lambda _: self.listed)

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
                (IMAPMailbox.init_flags, "/", "root_subthing"),
                (IMAPMailbox.init_flags, "/", "root_another_thing")
            ])
        ))
        return d

    def testLSub(self):
        """
        Test LSub command
        """
        acc = self.server.theAccount

        def subs_mailbox():
            # why not client.subscribe instead?
            return acc.subscribe('root_subthing')

        def lsub():
            return self.client.lsub('root', '%')

        d = self._listSetup(lsub, strip(subs_mailbox))
        d.addCallback(self.assertEqual,
                      [(IMAPMailbox.init_flags, "/", "root_subthing")])
        return d

    def testStatus(self):
        """
        Test Status command
        """
        acc = self.server.theAccount

        def add_mailbox():
            return acc.addMailbox('root_subthings')

        # XXX FIXME ---- should populate this a little bit,
        # with unseen etc...

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def status():
            return self.client.status(
                'root_subthings', 'MESSAGES', 'UIDNEXT', 'UNSEEN')

        def statused(result):
            self.statused = result

        self.statused = None

        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
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

    def testFullAppend(self):
        """
        Test appending a full message to the mailbox
        """
        infile = util.sibpath(__file__, 'rfc822.message')
        message = open(infile)
        acc = self.server.theAccount
        mailbox_name = "appendmbox/subthing"

        def add_mailbox():
            return acc.addMailbox(mailbox_name)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def append():
            return self.client.append(
                mailbox_name, message,
                ('\\SEEN', '\\DELETED'),
                'Tue, 17 Jun 2003 11:22:16 -0600 (MDT)',
            )

        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(append), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])

        d.addCallback(lambda _: acc.getMailbox(mailbox_name))
        d.addCallback(lambda mb: mb.fetch(imap4.MessageSet(start=1), True))
        return d.addCallback(self._cbTestFullAppend, infile)

    def _cbTestFullAppend(self, fetched, infile):
        fetched = list(fetched)
        self.assertTrue(len(fetched) == 1)
        self.assertTrue(len(fetched[0]) == 2)
        uid, msg = fetched[0]
        parsed = self.parser.parse(open(infile))
        expected_body = parsed.get_payload()
        expected_headers = CaseInsensitiveDict(parsed.items())

        def assert_flags(flags):
            self.assertEqual(
                set(('\\SEEN', '\\DELETED')),
                set(flags))

        def assert_date(date):
            self.assertEqual(
                'Tue, 17 Jun 2003 11:22:16 -0600 (MDT)',
                date)

        def assert_body(body):
            gotbody = body.read()
            self.assertEqual(expected_body, gotbody)

        def assert_headers(headers):
            self.assertItemsEqual(map(string.lower, expected_headers), headers)

        d = defer.maybeDeferred(msg.getFlags)
        d.addCallback(assert_flags)

        d.addCallback(lambda _: defer.maybeDeferred(msg.getInternalDate))
        d.addCallback(assert_date)

        d.addCallback(
            lambda _: defer.maybeDeferred(
                msg.getBodyFile, self._soledad))
        d.addCallback(assert_body)

        d.addCallback(lambda _: defer.maybeDeferred(msg.getHeaders, True))
        d.addCallback(assert_headers)

        return d

    def testPartialAppend(self):
        """
        Test partially appending a message to the mailbox
        """
        # TODO this test sometimes will fail because of the notify_just_mdoc
        infile = util.sibpath(__file__, 'rfc822.message')

        acc = self.server.theAccount

        def add_mailbox():
            return acc.addMailbox('PARTIAL/SUBTHING')

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
        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallbacks(strip(append), self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])

        d.addCallback(lambda _: acc.getMailbox("PARTIAL/SUBTHING"))
        d.addCallback(lambda mb: mb.fetch(imap4.MessageSet(start=1), True))
        return d.addCallback(
            self._cbTestPartialAppend, infile)

    def _cbTestPartialAppend(self, fetched, infile):
        fetched = list(fetched)
        self.assertTrue(len(fetched) == 1)
        self.assertTrue(len(fetched[0]) == 2)
        uid, msg = fetched[0]
        parsed = self.parser.parse(open(infile))
        expected_body = parsed.get_payload()

        def assert_flags(flags):
            self.assertEqual(
                set((['\\SEEN'])), set(flags))

        def assert_body(body):
            gotbody = body.read()
            self.assertEqual(expected_body, gotbody)

        d = defer.maybeDeferred(msg.getFlags)
        d.addCallback(assert_flags)

        d.addCallback(lambda _: defer.maybeDeferred(msg.getBodyFile))
        d.addCallback(assert_body)
        return d

    def testCheck(self):
        """
        Test check command
        """
        def add_mailbox():
            return self.server.theAccount.addMailbox('root/subthing')

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            return self.client.select('root/subthing')

        def check():
            return self.client.check()

        d = self.connected.addCallbacks(
            strip(add_mailbox), self._ebGeneral)
        d.addCallbacks(lambda _: login(), self._ebGeneral)
        d.addCallbacks(strip(select), self._ebGeneral)
        d.addCallbacks(strip(check), self._ebGeneral)
        d.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        return defer.gatherResults([d, d2])

        # Okay, that was much fun indeed

    def testExpunge(self):
        """
        Test expunge command
        """
        acc = self.server.theAccount
        mailbox_name = 'mailboxexpunge'

        def add_mailbox():
            return acc.addMailbox(mailbox_name)

        def login():
            return self.client.login(TEST_USER, TEST_PASSWD)

        def select():
            return self.client.select(mailbox_name)

        def save_mailbox(mailbox):
            self.mailbox = mailbox

        def get_mailbox():
            d = acc.getMailbox(mailbox_name)
            d.addCallback(save_mailbox)
            return d

        def add_messages():
            d = self.mailbox.addMessage(
                'test 1', flags=('\\Deleted', 'AnotherFlag'),
                notify_just_mdoc=False)
            d.addCallback(lambda _: self.mailbox.addMessage(
                'test 2', flags=('AnotherFlag',),
                notify_just_mdoc=False))
            d.addCallback(lambda _: self.mailbox.addMessage(
                'test 3', flags=('\\Deleted',),
                notify_just_mdoc=False))
            return d

        def expunge():
            return self.client.expunge()

        def expunged(results):
            self.failIf(self.server.mbox is None)
            self.results = results

        self.results = None
        d1 = self.connected.addCallback(strip(add_mailbox))
        d1.addCallback(strip(login))
        d1.addCallback(strip(get_mailbox))
        d1.addCallbacks(strip(add_messages), self._ebGeneral)
        d1.addCallbacks(strip(select), self._ebGeneral)
        d1.addCallbacks(strip(expunge), self._ebGeneral)
        d1.addCallbacks(expunged, self._ebGeneral)
        d1.addCallbacks(self._cbStopClient, self._ebGeneral)
        d2 = self.loopback()
        d = defer.gatherResults([d1, d2])
        d.addCallback(lambda _: self.mailbox.getMessageCount())
        return d.addCallback(self._cbTestExpunge)

    def _cbTestExpunge(self, count):
        # we only left 1 mssage with no deleted flag
        self.assertEqual(count, 1)
        # the uids of the deleted messages
        self.assertItemsEqual(self.results, [1, 3])


class AccountTestCase(IMAP4HelperMixin):
    """
    Test the Account.
    """
    def _create_empty_mailbox(self):
        return self.server.theAccount.addMailbox('')

    def _create_one_mailbox(self):
        return self.server.theAccount.addMailbox('one')

    def test_illegalMailboxCreate(self):
        self.assertRaises(AssertionError, self._create_empty_mailbox)


class IMAP4ServerSearchTestCase(IMAP4HelperMixin):
    """
    Tests for the behavior of the search_* functions in L{imap5.IMAP4Server}.
    """
    # XXX coming soon to your screens!
    pass
