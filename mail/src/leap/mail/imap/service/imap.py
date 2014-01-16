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
from copy import copy

import logging

from twisted.internet.protocol import ServerFactory
from twisted.internet.defer import maybeDeferred
from twisted.internet.error import CannotListenError
from twisted.mail import imap4
from twisted.python import log
from twisted import cred

logger = logging.getLogger(__name__)

from leap.common import events as leap_events
from leap.common.check import leap_assert, leap_assert_type, leap_check
from leap.keymanager import KeyManager
from leap.mail.imap.account import SoledadBackedAccount
from leap.mail.imap.fetch import LeapIncomingMail
from leap.soledad.client import Soledad

# The default port in which imap service will run
IMAP_PORT = 1984

# The period between succesive checks of the incoming mail
# queue (in seconds)
INCOMING_CHECK_PERIOD = 60

from leap.common.events.events_pb2 import IMAP_SERVICE_STARTED
from leap.common.events.events_pb2 import IMAP_SERVICE_FAILED_TO_START
from leap.common.events.events_pb2 import IMAP_CLIENT_LOGIN


class LeapIMAPServer(imap4.IMAP4Server):
    """
    An IMAP4 Server with mailboxes backed by soledad
    """
    def __init__(self, *args, **kwargs):
        # pop extraneous arguments
        soledad = kwargs.pop('soledad', None)
        uuid = kwargs.pop('uuid', None)
        userid = kwargs.pop('userid', None)
        leap_assert(soledad, "need a soledad instance")
        leap_assert_type(soledad, Soledad)
        leap_assert(uuid, "need a user in the initialization")

        self._userid = userid

        # initialize imap server!
        imap4.IMAP4Server.__init__(self, *args, **kwargs)

        # we should initialize the account here,
        # but we move it to the factory so we can
        # populate the test account properly (and only once
        # per session)

    def lineReceived(self, line):
        """
        Attempt to parse a single line from the server.

        :param line: the line from the server, without the line delimiter.
        :type line: str
        """
        if self.theAccount.closed is True and self.state != "unauth":
            log.msg("Closing the session. State: unauth")
            self.state = "unauth"

        if "login" in line.lower():
            # avoid to log the pass, even though we are using a dummy auth
            # by now.
            msg = line[:7] + " [...]"
        else:
            msg = copy(line)
        log.msg('rcv (%s): %s' % (self.state, msg))
        imap4.IMAP4Server.lineReceived(self, line)

    def authenticateLogin(self, username, password):
        """
        Lookup the account with the given parameters, and deny
        the improper combinations.

        :param username: the username that is attempting authentication.
        :type username: str
        :param password: the password to authenticate with.
        :type password: str
        """
        # XXX this should use portal:
        # return portal.login(cred.credentials.UsernamePassword(user, pass)
        if username != self._userid:
            # bad username, reject.
            raise cred.error.UnauthorizedLogin()
        # any dummy password is allowed so far. use realm instead!
        leap_events.signal(IMAP_CLIENT_LOGIN, "1")
        return imap4.IAccount, self.theAccount, lambda: None

    def do_FETCH(self, tag, messages, query, uid=0):
        """
        Overwritten fetch dispatcher to use the fast fetch_flags
        method
        """
        log.msg("LEAP Overwritten fetch...")
        if not query:
            self.sendPositiveResponse(tag, 'FETCH complete')
            return  # XXX ???

        cbFetch = self._IMAP4Server__cbFetch
        ebFetch = self._IMAP4Server__ebFetch

        print "QUERY: ", query

        if len(query) == 1 and str(query[0]) == "flags":
            self._oldTimeout = self.setTimeout(None)
            # no need to call iter, we get a generator
            maybeDeferred(
                self.mbox.fetch_flags, messages, uid=uid
            ).addCallback(
                cbFetch, tag, query, uid
            ).addErrback(ebFetch, tag)
        else:
            self._oldTimeout = self.setTimeout(None)
            # no need to call iter, we get a generator
            maybeDeferred(
                self.mbox.fetch, messages, uid=uid
            ).addCallback(
                cbFetch, tag, query, uid
            ).addErrback(ebFetch, tag)

    select_FETCH = (do_FETCH, imap4.IMAP4Server.arg_seqset,
                    imap4.IMAP4Server.arg_fetchatt)

    def _cbSelectWork(self, mbox, cmdName, tag):
        """
        Callback for selectWork, patched to avoid conformance errors due to
        incomplete UIDVALIDITY line.
        """
        if mbox is None:
            self.sendNegativeResponse(tag, 'No such mailbox')
            return
        if '\\noselect' in [s.lower() for s in mbox.getFlags()]:
            self.sendNegativeResponse(tag, 'Mailbox cannot be selected')
            return

        flags = mbox.getFlags()
        self.sendUntaggedResponse(str(mbox.getMessageCount()) + ' EXISTS')
        self.sendUntaggedResponse(str(mbox.getRecentCount()) + ' RECENT')
        self.sendUntaggedResponse('FLAGS (%s)' % ' '.join(flags))

        # Patched -------------------------------------------------------
        # imaptest was complaining about the incomplete line, we're adding
        # "UIDs valid" here.
        self.sendPositiveResponse(
            None, '[UIDVALIDITY %d] UIDs valid' % mbox.getUIDValidity())
        # ----------------------------------------------------------------

        s = mbox.isWriteable() and 'READ-WRITE' or 'READ-ONLY'
        mbox.addListener(self)
        self.sendPositiveResponse(tag, '[%s] %s successful' % (s, cmdName))
        self.state = 'select'
        self.mbox = mbox


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

    def __init__(self, uuid, userid, soledad):
        """
        Initializes the server factory.

        :param uuid: user uuid
        :type uuid: str

        :param userid: user id (user@provider.org)
        :type userid: str

        :param soledad: soledad instance
        :type soledad: Soledad
        """
        self._uuid = uuid
        self._userid = userid
        self._soledad = soledad

        theAccount = SoledadBackedAccount(
            uuid, soledad=soledad)
        self.theAccount = theAccount

    def buildProtocol(self, addr):
        "Return a protocol suitable for the job."
        imapProtocol = LeapIMAPServer(
            uuid=self._uuid,
            userid=self._userid,
            soledad=self._soledad)
        imapProtocol.theAccount = self.theAccount
        imapProtocol.factory = self
        return imapProtocol


def run_service(*args, **kwargs):
    """
    Main entry point to run the service from the client.

    :returns: the LoopingCall instance that will have to be stoppped
              before shutting down the client, the port as returned by
              the reactor when starts listening, and the factory for
              the protocol.
    """
    leap_assert(len(args) == 2)
    soledad, keymanager = args
    leap_assert_type(soledad, Soledad)
    leap_assert_type(keymanager, KeyManager)

    port = kwargs.get('port', IMAP_PORT)
    check_period = kwargs.get('check_period', INCOMING_CHECK_PERIOD)
    userid = kwargs.get('userid', None)
    leap_check(userid is not None, "need an user id")
    offline = kwargs.get('offline', False)

    uuid = soledad._get_uuid()
    factory = LeapIMAPFactory(uuid, userid, soledad)

    from twisted.internet import reactor

    try:
        tport = reactor.listenTCP(port, factory,
                                  interface="localhost")
        if not offline:
            fetcher = LeapIncomingMail(
                keymanager,
                soledad,
                factory.theAccount,
                check_period,
                userid)
        else:
            fetcher = None
    except CannotListenError:
        logger.error("IMAP Service failed to start: "
                     "cannot listen in port %s" % (port,))
    except Exception as exc:
        logger.error("Error launching IMAP service: %r" % (exc,))
    else:
        # all good.
        # (the caller has still to call fetcher.start_loop)
        logger.debug("IMAP4 Server is RUNNING in port  %s" % (port,))
        leap_events.signal(IMAP_SERVICE_STARTED, str(port))
        return fetcher, tport, factory

    # not ok, signal error.
    leap_events.signal(IMAP_SERVICE_FAILED_TO_START, str(port))
