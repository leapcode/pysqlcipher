# -*- coding: utf-8 -*-
# utils.py
# Copyright (C) 2014, 2015 LEAP
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
Common utilities for testing Soledad IMAP Server.
"""
from email import parser

from mock import Mock
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.error import UnauthorizedLogin
from twisted.cred.portal import Portal, IRealm
from twisted.mail import imap4
from twisted.internet import defer
from twisted.protocols import loopback
from twisted.python import log
from zope.interface import implementer

from leap.mail.adaptors import soledad as soledad_adaptor
from leap.mail.imap.account import IMAPAccount
from leap.mail.imap.server import LEAPIMAPServer
from leap.mail.tests.common import SoledadTestMixin

TEST_USER = "testuser@leap.se"
TEST_PASSWD = "1234"


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

#
# Dummy credentials for tests
#


@implementer(IRealm)
class TestRealm(object):

    def __init__(self, account):
        self._account = account

    def requestAvatar(self, avatarId, mind, *interfaces):
        avatar = self._account
        return (imap4.IAccount, avatar,
                getattr(avatar, 'logout', lambda: None))


@implementer(ICredentialsChecker)
class TestCredentialsChecker(object):

    credentialInterfaces = (IUsernamePassword,)

    userid = TEST_USER
    password = TEST_PASSWD

    def requestAvatarId(self, credentials):
        username, password = credentials.username, credentials.password
        d = self.checkTestCredentials(username, password)
        d.addErrback(lambda f: defer.fail(UnauthorizedLogin()))
        return d

    def checkTestCredentials(self, username, password):
        if username == self.userid and password == self.password:
            return defer.succeed(username)
        else:
            return defer.fail(Exception("Wrong credentials"))


class TestSoledadIMAPServer(LEAPIMAPServer):

    def __init__(self, account, *args, **kw):

        LEAPIMAPServer.__init__(self, *args, **kw)

        realm = TestRealm(account)
        portal = Portal(realm)
        checker = TestCredentialsChecker()
        self.checker = checker
        self.portal = portal
        portal.registerChecker(checker)


class IMAP4HelperMixin(SoledadTestMixin):
    """
    MixIn containing several utilities to be shared across
    different TestCases
    """
    serverCTX = None
    clientCTX = None

    def setUp(self):

        soledad_adaptor.cleanup_deferred_locks()

        USERID = TEST_USER

        def setup_server(account):
            self.server = TestSoledadIMAPServer(
                account=account,
                contextFactory=self.serverCTX)
            self.server.theAccount = account

            d_server_ready = defer.Deferred()
            self.client = SimpleClient(
                d_server_ready, contextFactory=self.clientCTX)
            self.connected = d_server_ready

        def setup_account(_):
            self.parser = parser.Parser()

            # XXX this should be fixed in soledad.
            # Soledad sync makes trial block forever. The sync it's mocked to
            # fix this problem. _mock_soledad_get_from_index can be used from
            # the tests to provide documents.
            # TODO see here, possibly related?
            # -- http://www.pythoneye.com/83_20424875/
            self._soledad.sync = Mock()

            d = defer.Deferred()
            self.acc = IMAPAccount(self._soledad, USERID, d=d)
            return d

        d = super(IMAP4HelperMixin, self).setUp()
        d.addCallback(setup_account)
        d.addCallback(setup_server)
        return d

    def tearDown(self):
        SoledadTestMixin.tearDown(self)
        del self._soledad
        del self.client
        del self.server
        del self.connected

    def _cbStopClient(self, ignore):
        self.client.transport.loseConnection()

    def _ebGeneral(self, failure):
        self.client.transport.loseConnection()
        self.server.transport.loseConnection()
        if hasattr(self, 'function'):
            log.err(failure, "Problem with %r" % (self.function,))

    def loopback(self):
        return loopback.loopbackAsync(self.server, self.client)
