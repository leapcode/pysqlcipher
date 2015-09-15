# -*- coding: utf-8 -*-
# imap.py
# Copyright (C) 2013-2015 LEAP
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
IMAP service initialization
"""
import logging
import os

from collections import defaultdict

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import ServerFactory
from twisted.mail import imap4
from twisted.python import log

from leap.common.events import emit_async, catalog
from leap.common.check import leap_check
from leap.mail.imap.account import IMAPAccount
from leap.mail.imap.server import LEAPIMAPServer

# TODO: leave only an implementor of IService in here

logger = logging.getLogger(__name__)

DO_MANHOLE = os.environ.get("LEAP_MAIL_MANHOLE", None)
if DO_MANHOLE:
    from leap.mail.imap.service import manhole

DO_PROFILE = os.environ.get("LEAP_PROFILE", None)
if DO_PROFILE:
    import cProfile
    log.msg("Starting PROFILING...")

    PROFILE_DAT = "/tmp/leap_mail_profile.pstats"
    pr = cProfile.Profile()
    pr.enable()

# The default port in which imap service will run
IMAP_PORT = 1984


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
    protocol = LEAPIMAPServer

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

        theAccount = IMAPAccount(uuid, soledad)
        self.theAccount = theAccount
        self._connections = defaultdict()
        # XXX how to pass the store along?

    def buildProtocol(self, addr):
        """
        Return a protocol suitable for the job.

        :param addr: remote ip address
        :type addr:  str
        """
        # TODO should reject anything from addr != localhost,
        # just in case.
        log.msg("Building protocol for connection %s" % addr)
        imapProtocol = self.protocol(
            uuid=self._uuid,
            userid=self._userid,
            soledad=self._soledad)
        imapProtocol.theAccount = self.theAccount
        imapProtocol.factory = self

        self._connections[addr] = imapProtocol
        return imapProtocol

    def stopFactory(self):
        # say bye!
        for conn, proto in self._connections.items():
            log.msg("Closing connections for %s" % conn)
            proto.close_server_connection()

    def doStop(self):
        """
        Stops imap service (fetcher, factory and port).
        """
        # mark account as unusable, so any imap command will fail
        # with unauth state.
        self.theAccount.end_session()

        # TODO should wait for all the pending deferreds,
        # the twisted way!
        if DO_PROFILE:
            log.msg("Stopping PROFILING")
            pr.disable()
            pr.dump_stats(PROFILE_DAT)

        return ServerFactory.doStop(self)


def run_service(store, **kwargs):
    """
    Main entry point to run the service from the client.

    :param store: a soledad instance

    :returns: the port as returned by the reactor when starts listening, and
              the factory for the protocol.
    """
    leap_check(store, "store cannot be None")
    # XXX this can also be a ProxiedObject, FIXME
    # leap_assert_type(store, Soledad)

    port = kwargs.get('port', IMAP_PORT)
    userid = kwargs.get('userid', None)
    leap_check(userid is not None, "need an user id")

    uuid = store.uuid
    factory = LeapIMAPFactory(uuid, userid, store)

    try:
        tport = reactor.listenTCP(port, factory,
                                  interface="localhost")
    except CannotListenError:
        logger.error("IMAP Service failed to start: "
                     "cannot listen in port %s" % (port,))
    except Exception as exc:
        logger.error("Error launching IMAP service: %r" % (exc,))
    else:
        # all good.

        if DO_MANHOLE:
            # TODO get pass from env var.too.
            manhole_factory = manhole.getManholeFactory(
                {'f': factory,
                 'a': factory.theAccount,
                 'gm': factory.theAccount.getMailbox},
                "boss", "leap")
            reactor.listenTCP(manhole.MANHOLE_PORT, manhole_factory,
                              interface="127.0.0.1")
        logger.debug("IMAP4 Server is RUNNING in port  %s" % (port,))
        emit_async(catalog.IMAP_SERVICE_STARTED, str(port))

        # FIXME -- change service signature
        return tport, factory

    # not ok, signal error.
    emit_async(catalog.IMAP_SERVICE_FAILED_TO_START, str(port))
