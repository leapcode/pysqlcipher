# -*- coding: utf-8 -*-
# service.py
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
Bonafide Service.
"""

import os

from leap.bonafide._protocol import BonafideProtocol

from twisted.application import service
from twisted.internet import defer
from twisted.python import log


class BonafideService(service.Service):

    # TODO inherit from HookableService (from common)

    def __init__(self, basedir='~/.config/leap'):
        self._bonafide = BonafideProtocol()
        self._basedir = os.path.expanduser(basedir)
        self.service_hooks = {}

        # XXX this is a quick hack to get a ref
        # to the latest authenticated user.
        self._active_user = None

    def register_hook(self, kind, trigger):
        self.service_hooks[kind] = trigger

    def get_hooked_service(self, kind):
        hooks = self.service_hooks
        if kind in hooks:
            return self.get_sibling_service(hooks[kind])

    def get_sibling_service(self, kind):
        return self.parent.getServiceNamed(kind)

    def startService(self):
        log.msg('Starting Bonafide Service')
        super(BonafideService, self).startService()

    # Commands

    def do_authenticate(self, username, password):

        def notify_passphrase_entry(username, password):
            this_hook = 'on_passphrase_entry'
            hooked_service = self.get_hooked_service(this_hook)
            if hooked_service:
                hooked_service.notify_hook(
                    this_hook, username=username, password=password)

        def notify_bonafide_auth_hook(result):
            if not result:
                log.msg("Authentication hook did not return anything")
                return

            this_hook = 'on_bonafide_auth'
            token, uuid = result
            hooked_service = self.get_hooked_service(this_hook)
            if hooked_service:
                hooked_service.notify_hook(
                    this_hook,
                    username=username, token=token, uuid=uuid,
                    password=password)
            self._active_user = username
            return result

        # XXX I still have doubts from where it's best to trigger this.
        # We probably should wait for BOTH deferreds and
        # handle local and remote authentication success together
        # (and fail if either one fails). Going with fire-and-forget for
        # now, but needs needs improvement.

        notify_passphrase_entry(username, password)

        d = self._bonafide.do_authenticate(username, password)
        d.addCallback(notify_bonafide_auth_hook)
        d.addCallback(lambda response: '[ SRP TOKEN: %s ] [ UUID: %s ]' %
                      (response[0], response[1]))
        return d

    def do_signup(self, username, password):
        d = self._bonafide.do_signup(username, password)
        d.addCallback(lambda response: 'REGISTERED -> %s' % response)
        return d

    def do_logout(self, username, password):
        if not username:
            username = self._active_user

        def reset_active(passthrough):
            self._active_user = None
            return passthrough

        d = self._bonafide.do_logout(username, password)
        d.addCallback(reset_active)
        d.addCallback(lambda response: 'LOGOUT -> ok')
        return d

    def do_get_smtp_cert(self, username=None):
        if not username:
            username = self._active_user
        if not username:
            return defer.fail(
                RuntimeError('No active user, cannot get SMTP cert.'))

        d = self._bonafide.do_get_smtp_cert(username)
        d.addCallback(lambda response: (username, response))
        return d

    def do_get_active_user(self):
        user = self._active_user
        return defer.succeed(user)
