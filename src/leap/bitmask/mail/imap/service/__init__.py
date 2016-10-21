# -*- coding: utf-8 -*-
# __init__.py
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
IMAP Service Initialization.
"""
import os

from collections import defaultdict

from twisted.cred.portal import Portal, IRealm
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import ServerFactory
from twisted.logger import Logger
from twisted.mail.imap4 import IAccount
from zope.interface import implementer

from leap.common.events import emit_async, catalog
from leap.bitmask.mail.cred import LocalSoledadTokenChecker
from leap.bitmask.mail.imap.account import IMAPAccount
from leap.bitmask.mail.imap.server import LEAPIMAPServer

# TODO: leave only an implementor of IService in here

logger = Logger()

DO_MANHOLE = os.environ.get("LEAP_MAIL_MANHOLE", None)
if DO_MANHOLE:
    from leap.bitmask.mail.imap.service import manhole

# The default port in which imap service will run

IMAP_PORT = 1984

#
# Credentials Handling
#


@implementer(IRealm)
class LocalSoledadIMAPRealm(object):

    _encoding = 'utf-8'

    def __init__(self, soledad_sessions):
        """
        :param soledad_sessions: a dict-like object, containing instances
                                 of a Store (soledad instances), indexed by
                                 userid.
        """
        self._soledad_sessions = soledad_sessions

    def requestAvatar(self, avatarId, mind, *interfaces):
        if isinstance(avatarId, str):
            avatarId = avatarId.decode(self._encoding)

        def gotSoledad(soledad):
            for iface in interfaces:
                if iface is IAccount:
                    avatar = IMAPAccount(soledad, avatarId)
                    return (IAccount, avatar,
                            getattr(avatar, 'logout', lambda: None))
            raise NotImplementedError(self, interfaces)

        return self.lookupSoledadInstance(avatarId).addCallback(gotSoledad)

    def lookupSoledadInstance(self, userid):
        soledad = self._soledad_sessions[userid]
        # XXX this should return the instance after whenReady callback
        return defer.succeed(soledad)


class IMAPTokenChecker(LocalSoledadTokenChecker):
    """A credentials checker that will lookup a token for the IMAP service.
    For now it will be using the same identifier than SMTPTokenChecker"""

    service = 'mail_auth'


class LocalSoledadIMAPServer(LEAPIMAPServer):

    """
    An IMAP Server that authenticates against a LocalSoledad store.
    """

    def __init__(self, soledad_sessions, *args, **kw):

        LEAPIMAPServer.__init__(self, *args, **kw)

        realm = LocalSoledadIMAPRealm(soledad_sessions)
        portal = Portal(realm)
        checker = IMAPTokenChecker(soledad_sessions)
        self.checker = checker
        self.portal = portal
        portal.registerChecker(checker)


class LeapIMAPFactory(ServerFactory):

    """
    Factory for a IMAP4 server with soledad remote sync and gpg-decryption
    capabilities.
    """

    protocol = LocalSoledadIMAPServer

    def __init__(self, soledad_sessions):
        """
        Initializes the server factory.

        :param soledad_sessions: a dict-like object, containing instances
                                 of a Store (soledad instances), indexed by
                                 userid.
        """
        self._soledad_sessions = soledad_sessions
        self._connections = defaultdict()

    def buildProtocol(self, addr):
        """
        Return a protocol suitable for the job.

        :param addr: remote ip address
        :type addr:  str
        """
        # TODO should reject anything from addr != localhost,
        # just in case.
        logger.debug("Building protocol for connection %s" % addr)
        imapProtocol = self.protocol(self._soledad_sessions)
        self._connections[addr] = imapProtocol
        return imapProtocol

    def stopFactory(self):
        # say bye!
        for conn, proto in self._connections.items():
            logger.debug("Closing connections for %s" % conn)
            proto.close_server_connection()

    def doStop(self):
        """
        Stops imap service (fetcher, factory and port).
        """
        return ServerFactory.doStop(self)


def run_service(soledad_sessions, port=IMAP_PORT, factory=None):
    """
    Main entry point to run the service from the client.

    :param soledad_sessions: a dict-like object, containing instances
                             of a Store (soledad instances), indexed by userid.

    :returns: the port as returned by the reactor when starts listening, and
              the factory for the protocol.
    :rtype: tuple
    """
    if not factory:
        factory = LeapIMAPFactory(soledad_sessions)

    try:
        interface = "localhost"
        # don't bind just to localhost if we are running on docker since we
        # won't be able to access imap from the host
        if os.environ.get("LEAP_DOCKERIZED"):
            interface = ''

        # TODO use Endpoints !!!
        tport = reactor.listenTCP(port, factory,
                                  interface=interface)
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
                 'gm': factory.theAccount.getMailbox},
                "boss", "leap")
            # TODO  use Endpoints !!!
            reactor.listenTCP(manhole.MANHOLE_PORT, manhole_factory,
                              interface="127.0.0.1")
        logger.debug("IMAP4 Server is RUNNING in port  %s" % (port,))
        emit_async(catalog.IMAP_SERVICE_STARTED, str(port))

        # FIXME -- change service signature
        return tport, factory

    # not ok, signal error.
    emit_async(catalog.IMAP_SERVICE_FAILED_TO_START, str(port))
