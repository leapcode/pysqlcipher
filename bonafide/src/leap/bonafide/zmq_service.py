# -*- coding: utf-8 -*-
# zmq_service.py
# Copyright (C) 2015 LEAP
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
Bonafide ZMQ Service.
"""
from leap.bonafide import config
from leap.bonafide.protocol import BonafideProtocol, COMMANDS

from txzmq import ZmqEndpoint, ZmqFactory, ZmqREPConnection

from twisted.application import service
from twisted.internet import reactor
from twisted.python import log


class BonafideZMQService(service.Service):

    def __init__(self):
        self._bonafide = BonafideProtocol()
        self._conn = None

    def startService(self):
        zf = ZmqFactory()
        e = ZmqEndpoint("bind", config.ENDPOINT)
        self._conn = _BonafideZmqREPConnection(zf, e, self._bonafide)
        reactor.callWhenRunning(self._conn.do_greet)


class _BonafideZmqREPConnection(ZmqREPConnection):

    def __init__(self, zf, e, bonafide):
        ZmqREPConnection.__init__(self, zf, e)
        self._bonafide = bonafide

    def do_greet(self):
        print "Bonafide service running..."

    def do_bye(self):
        print "[+] Bonafide service stopped. Have a nice day."
        reactor.stop()

    def gotMessage(self, msgId, *parts):
        def defer_reply(response):
            reactor.callLater(0, self.reply, msgId, str(response))

        def log_err(failure):
            log.err(failure)
            print "FAILURE", failure
            defer_reply("ERROR: %r" % failure)

        cmd = parts[0]

        if cmd == "shutdown":
            defer_reply('ok, shutting down')
            reactor.callLater(1, self.do_bye)

        if cmd not in COMMANDS:
            response = 'INVALID COMMAND'
            defer_reply(response)

        elif cmd == 'signup':
            username, password = parts[1], parts[2]
            d = self._bonafide.do_signup(username, password)
            d.addCallback(lambda response: defer_reply(
                'REGISTERED -> %s' % response))
            d.addErrback(log_err)

        elif cmd == 'authenticate':
            username, password = parts[1], parts[2]
            d = self._bonafide.do_authenticate(username, password)
            d.addCallback(lambda response: defer_reply(
                'TOKEN -> %s' % response))
            d.addErrback(log_err)

        elif cmd == 'logout':
            username, password = parts[1], parts[2]
            d = self._bonafide.do_logout(username, password)
            d.addCallback(lambda response: defer_reply(
                'LOGOUT -> ok'))
            d.addErrback(log_err)

        elif cmd == 'stats':
            response = self._bonafide.do_stats()
            defer_reply(response)
