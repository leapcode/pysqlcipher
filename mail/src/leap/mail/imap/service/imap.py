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
import os

from twisted.internet.protocol import ServerFactory
from twisted.internet.error import CannotListenError
from twisted.mail import imap4

logger = logging.getLogger(__name__)

from leap.common import events as leap_events
from leap.common.check import leap_assert, leap_assert_type, leap_check
from leap.keymanager import KeyManager
from leap.mail.imap.account import SoledadBackedAccount
from leap.mail.imap.fetch import LeapIncomingMail
from leap.mail.imap.memorystore import MemoryStore
from leap.mail.imap.server import LeapIMAPServer
from leap.mail.imap.soledadstore import SoledadStore
from leap.soledad.client import Soledad

# The default port in which imap service will run
IMAP_PORT = 1984

# The period between succesive checks of the incoming mail
# queue (in seconds)
INCOMING_CHECK_PERIOD = 60

from leap.common.events.events_pb2 import IMAP_SERVICE_STARTED
from leap.common.events.events_pb2 import IMAP_SERVICE_FAILED_TO_START

######################################################
# Temporary workaround for RecursionLimit when using
# qt4reactor. Do remove when we move to poll or select
# reactor, which do not show those problems. See #4974
import resource
import sys

try:
    sys.setrecursionlimit(10**6)
except Exception:
    print "Error setting recursion limit"
try:
    # Increase max stack size from 8MB to 256MB
    resource.setrlimit(resource.RLIMIT_STACK, (2**28, -1))
except Exception:
    print "Error setting stack size"

######################################################

DO_MANHOLE = os.environ.get("LEAP_MAIL_MANHOLE", None)


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
        self._memstore = MemoryStore(
            permanent_store=SoledadStore(soledad))

        theAccount = SoledadBackedAccount(
            uuid, soledad=soledad,
            memstore=self._memstore)
        self.theAccount = theAccount

        # XXX how to pass the store along?

    def buildProtocol(self, addr):
        "Return a protocol suitable for the job."
        imapProtocol = LeapIMAPServer(
            uuid=self._uuid,
            userid=self._userid,
            soledad=self._soledad)
        imapProtocol.theAccount = self.theAccount
        imapProtocol.factory = self
        return imapProtocol


MANHOLE_PORT = 2222


def getManholeFactory(namespace, user, secret):
    """
    Get an administrative manhole into the application.

    :param namespace: the namespace to show in the manhole
    :type namespace: dict
    :param user: the user to authenticate into the administrative shell.
    :type user: str
    :param secret: pass for this manhole
    :type secret: str
    """
    import string

    from twisted.cred.portal import Portal
    from twisted.conch import manhole, manhole_ssh
    from twisted.conch.insults import insults
    from twisted.cred.checkers import (
        InMemoryUsernamePasswordDatabaseDontUse as MemoryDB)

    from rlcompleter import Completer

    class EnhancedColoredManhole(manhole.ColoredManhole):
        """
        A Manhole with some primitive autocomplete support.
        """
        # TODO use introspection to make life easier

        def find_common(self, l):
            """
            find common parts in thelist items
            ex: 'ab' for ['abcd','abce','abf']
            requires an ordered list
            """
            if len(l) == 1:
                return l[0]

            init = l[0]
            for item in l[1:]:
                for i, (x, y) in enumerate(zip(init, item)):
                    if x != y:
                        init = "".join(init[:i])
                        break

                if not init:
                    return None
            return init

        def handle_TAB(self):
            """
            Trap the TAB keystroke
            """
            necessarypart = "".join(self.lineBuffer).split(' ')[-1]
            completer = Completer(globals())
            if completer.complete(necessarypart, 0):
                matches = list(set(completer.matches))  # has multiples

                if len(matches) == 1:
                    length = len(necessarypart)
                    self.lineBuffer = self.lineBuffer[:-length]
                    self.lineBuffer.extend(matches[0])
                    self.lineBufferIndex = len(self.lineBuffer)
                else:
                    matches.sort()
                    commons = self.find_common(matches)
                    if commons:
                        length = len(necessarypart)
                        self.lineBuffer = self.lineBuffer[:-length]
                        self.lineBuffer.extend(commons)
                        self.lineBufferIndex = len(self.lineBuffer)

                    self.terminal.nextLine()
                    while matches:
                        matches, part = matches[4:], matches[:4]
                        for item in part:
                            self.terminal.write('%s' % item.ljust(30))
                            self.terminal.write('\n')
                            self.terminal.nextLine()

                self.terminal.eraseLine()
                self.terminal.cursorBackward(self.lineBufferIndex + 5)
                self.terminal.write("%s %s" % (
                    self.ps[self.pn], "".join(self.lineBuffer)))

        def keystrokeReceived(self, keyID, modifier):
            """
            Act upon any keystroke received.
            """
            self.keyHandlers.update({'\b': self.handle_BACKSPACE})
            m = self.keyHandlers.get(keyID)
            if m is not None:
                m()
            elif keyID in string.printable:
                self.characterReceived(keyID, False)

    sshRealm = manhole_ssh.TerminalRealm()

    def chainedProtocolFactory():
        return insults.ServerProtocol(EnhancedColoredManhole, namespace)

    sshRealm = manhole_ssh.TerminalRealm()
    sshRealm.chainedProtocolFactory = chainedProtocolFactory

    portal = Portal(
        sshRealm, [MemoryDB(**{user: secret})])

    f = manhole_ssh.ConchFactory(portal)
    return f


def run_service(*args, **kwargs):
    """
    Main entry point to run the service from the client.

    :returns: the LoopingCall instance that will have to be stoppped
              before shutting down the client, the port as returned by
              the reactor when starts listening, and the factory for
              the protocol.
    """
    from twisted.internet import reactor

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

        if DO_MANHOLE:
            # TODO get pass from env var.too.
            manhole_factory = getManholeFactory(
                {'f': factory,
                 'a': factory.theAccount,
                 'gm': factory.theAccount.getMailbox},
                "boss", "leap")
            reactor.listenTCP(MANHOLE_PORT, manhole_factory,
                              interface="127.0.0.1")
        logger.debug("IMAP4 Server is RUNNING in port  %s" % (port,))
        leap_events.signal(IMAP_SERVICE_STARTED, str(port))
        return fetcher, tport, factory

    # not ok, signal error.
    leap_events.signal(IMAP_SERVICE_FAILED_TO_START, str(port))
