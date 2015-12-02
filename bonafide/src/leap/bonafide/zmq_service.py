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
        super(BonafideZMQService, self).startService()

    def stopService(self):
        super(BonafideZMQService, self).stopService()

    def register_hook(self, kind, trigger):
        self.service_hooks[kind] = trigger



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
        print "Starting Bonafide service"

    def do_bye(self):
        print "Bonafide service stopped. Have a nice day."
        reactor.stop()

    def defer_reply(self, response, msgId):
        reactor.callLater(0, self.reply, msgId, str(response))

    def log_err(self, failure, msgId):
        log.err(failure)
        self.defer_reply("ERROR: %r" % failure, msgId)

    def gotMessage(self, msgId, *parts):

        cmd = parts[0]

        if cmd == "shutdown":
            self.do_shutdown(msgId)

        if cmd not in COMMANDS + ("get_soledad",):
            response = 'INVALID COMMAND'
            self.defer_reply(response, msgId)

        elif cmd == 'signup':
            self.do_signup(parts, msgId)

        elif cmd == 'authenticate':
            self.do_authenticate(parts, msgId)

        elif cmd == 'logout':
            self.do_logout(self, parts, msgId)

        elif cmd == 'stats':
            self.do_stats(msgId)

    def do_shutdown(self, msgId):
        self.defer_reply('ok, shutting down', msgId)
        reactor.callLater(1, self.do_bye)

    def do_signup(self, parts, msgId):
        username, password = parts[1], parts[2]
        d = self._bonafide.do_signup(username, password)
        d.addCallback(lambda response: self.defer_reply(
            'REGISTERED -> %s' % response), msgId)
        d.addErrback(self.log_err, msgId)

    def do_authenticate(self, parts, msgId):

        username, password = parts[1], parts[2]

        def notify_passphrase_entry(username, password):
            this_hook = 'on_passphrase_entry'
            hooked_service = self.get_hooked_service(this_hook)
            if hooked_service:
                hooked_service.notify_hook(
                    this_hook, username=username, password=password)

        def notify_bonafide_auth_hook(result):
            this_hook = 'on_bonafide_auth'
            token, uuid = result
            hooked_service = self.get_hooked_service(this_hook)
            if hooked_service:
                hooked_service.notify_hook(
                    this_hook,
                    username=username, token=token, uuid=uuid,
                    password=password)
            return result

        # XXX I still have doubts from where it's best to trigger this.
        # We probably should wait for BOTH deferreds and
        # handle local and remote authentication success together
        # (and fail if either one fails). Going with fire-and-forget for
        # now, but needs needs improvement.

        notify_passphrase_entry(username, password)

        d = self._bonafide.do_authenticate(username, password)
        d.addCallback(notify_bonafide_auth_hook)
        d.addCallback(lambda response: self.defer_reply(
            'TOKEN, UUID: %s' % str(response), msgId))
        d.addErrback(self.log_err, msgId)

    def do_logout(self, parts, msgId):
        username, password = parts[1], parts[2]
        d = self._bonafide.do_logout(username, password)
        d.addCallback(lambda response: self.defer_reply(
            'LOGOUT -> ok'), msgId)
        d.addErrback(self.log_err, msgId)

    def do_stats(self, msgId):
        response = self._bonafide.do_stats()
        self.defer_reply(response, msgId)
