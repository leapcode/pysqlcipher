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
from leap.bonafide._protocol import BonafideProtocol, COMMANDS

from txzmq import ZmqEndpoint, ZmqFactory, ZmqREPConnection

from twisted.application import service
from twisted.internet import reactor
from twisted.python import log


# TODO [] should shutdown all the ongoing connections when stopping the service

class BonafideZMQService(service.Service):

    def __init__(self):
        self._bonafide = BonafideProtocol()
        self._conn = None

        self.service_hooks = {}

    def startService(self):
        zf = ZmqFactory()
        e = ZmqEndpoint("bind", config.ENDPOINT)

        self._conn = _BonafideZmqREPConnection(zf, e, self._bonafide, self)
        reactor.callWhenRunning(self._conn.do_greet)

    def register_hook(self, kind, service):
        print "REGISTERING HOOK", kind, service
        self.service_hooks[kind] = service


    # def stopService(self):
    #     pass



class _BonafideZmqREPConnection(ZmqREPConnection):

    def __init__(self, zf, e, bonafide, service):
        # XXX passing a ref to the service,
        # to be able to access sibling services
        ZmqREPConnection.__init__(self, zf, e)
        self._bonafide = bonafide
        self._service = service

    def get_sibling_service(self, kind):
        return self._service.parent.getServiceNamed(kind)

    def get_hooked_service(self, kind):
        hooks = self._service.service_hooks
        if kind in hooks:
            return self.get_sibling_service(hooks[kind])

    def do_greet(self):
        print "Starging Bonafide service"

    def do_bye(self):
        print "Bonafide service stopped. Have a nice day."
        reactor.stop()

    def gotMessage(self, msgId, *parts):
        def defer_reply(response):
            reactor.callLater(0, self.reply, msgId, str(response))

        def log_err(failure):
            log.err(failure)
            defer_reply("ERROR: %r" % failure)

        cmd = parts[0]

        # TODO split using dispatcher pattern

        if cmd == "shutdown":
            defer_reply('ok, shutting down')
            reactor.callLater(1, self.do_bye)

        if cmd not in COMMANDS + ("get_soledad",):
            response = 'INVALID COMMAND'
            defer_reply(response)

        elif cmd == 'signup':
            username, password = parts[1], parts[2]
            d = self._bonafide.do_signup(username, password)
            d.addCallback(lambda response: defer_reply(
                'REGISTERED -> %s' % response))
            d.addErrback(log_err)

        elif cmd == 'authenticate':

            def activate_hook(token):
                hook_service = self.get_hooked_service('on_auth')
                if hook_service:
                    hook_service.activate_hook(
                        # TODO GET UUID TOO!!
                        'on_auth', username=username, uuid=uuid, token=token)
                return token

            username, password = parts[1], parts[2]
            d = self._bonafide.do_authenticate(username, password)
            d.addCallback(activate_hook)
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

        # XXX DEBUG ---------------------------------------------------------
        elif cmd == 'get_soledad':
            response = str(self._service.parent.getServiceNamed("soledad"))
            defer_reply(response)
        # ------------------------------------------------------------------
