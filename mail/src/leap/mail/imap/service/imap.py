# -*- coding: utf-8 -*-
# imap.py
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
Imap service initialization
"""
import logging
logger = logging.getLogger(__name__)

#from twisted.application import internet, service
from twisted.internet.protocol import ServerFactory
from twisted.internet.task import LoopingCall

from twisted.mail import imap4
from twisted.python import log

from leap.common.check import leap_assert, leap_assert_type
from leap.common.keymanager import KeyManager
from leap.mail.imap.server import SoledadBackedAccount
from leap.mail.imap.fetch import LeapIncomingMail
from leap.soledad import Soledad

IMAP_PORT = 9930
# The default port in which imap service will run

#INCOMING_CHECK_PERIOD = 10
INCOMING_CHECK_PERIOD = 5
# The period between succesive checks of the incoming mail
# queue (in seconds)


class LeapIMAPServer(imap4.IMAP4Server):
    """
    An IMAP4 Server with mailboxes backed by soledad
    """
    def __init__(self, *args, **kwargs):
        # pop extraneous arguments
        soledad = kwargs.pop('soledad', None)
        user = kwargs.pop('user', None)
        leap_assert(soledad, "need a soledad instance")
        leap_assert_type(soledad, Soledad)
        leap_assert(user, "need a user in the initialization")

        # initialize imap server!
        imap4.IMAP4Server.__init__(self, *args, **kwargs)

        # we should initialize the account here,
        # but we move it to the factory so we can
        # populate the test account properly (and only once
        # per session)

        # theAccount = SoledadBackedAccount(
        #     user, soledad=soledad)

        # ---------------------------------
        # XXX pre-populate acct for tests!!
        # populate_test_account(theAccount)
        # ---------------------------------
        #self.theAccount = theAccount

    def lineReceived(self, line):
        log.msg('rcv: %s' % line)
        imap4.IMAP4Server.lineReceived(self, line)

    def authenticateLogin(self, username, password):
        # all is allowed so far. use realm instead
        return imap4.IAccount, self.theAccount, lambda: None


class IMAPAuthRealm(object):
    """
    Dummy authentication realm. Do not use in production!
    """
    theAccount = None

    def requestAvatar(self, avatarId, mind, *interfaces):
        return imap4.IAccount, self.theAccount, lambda: None


class LeapIMAPFactory(ServerFactory):
    """
    Factory for a IMAP4 server with soledad remote sync and gpg-decryption
    capabilities.
    """

    def __init__(self, user, soledad):
        """
        Initializes the server factory.

        :param user: user ID. **right now it's uuid**
                     this might change!
        :type user: str

        :param soledad: soledad instance
        :type soledad: Soledad
        """
        self._user = user
        self._soledad = soledad

        theAccount = SoledadBackedAccount(
            user, soledad=soledad)
        self.theAccount = theAccount

    def buildProtocol(self, addr):
        "Return a protocol suitable for the job."
        imapProtocol = LeapIMAPServer(
            user=self._user,
            soledad=self._soledad)
        imapProtocol.theAccount = self.theAccount
        imapProtocol.factory = self
        return imapProtocol


def run_service(*args, **kwargs):
    """
    Main entry point to run the service from the client.
    """
    leap_assert(len(args) == 2)
    soledad, keymanager = args
    leap_assert_type(soledad, Soledad)
    leap_assert_type(keymanager, KeyManager)

    port = kwargs.get('port', IMAP_PORT)
    check_period = kwargs.get('check_period', INCOMING_CHECK_PERIOD)

    uuid = soledad._get_uuid()
    factory = LeapIMAPFactory(uuid, soledad)

    # ---- for application framework
    #application = service.Application("LEAP IMAP4 Local Service")
    #imapService = internet.TCPServer(port, factory)
    #imapService.setServiceParent(application)

    from twisted.internet import reactor
    reactor.listenTCP(port, factory)

    fetcher = LeapIncomingMail(
        keymanager,
        soledad,
        factory.theAccount)

    lc = LoopingCall(fetcher.fetch)
    lc.start(check_period)

    # ---- for application framework
    #internet.TimerService(
        #check_period,
        #fetcher.fetch).setServiceParent(application)

    logger.debug('----------------------------------------')
    logger.debug("IMAP4 Server is RUNNING in port  %s" % (port,))

    #log.msg("IMAP4 Server is RUNNING in port  %s" % (port,))
    #return application
