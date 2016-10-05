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
from collections import defaultdict

from leap.common.config import get_path_prefix
from leap.bitmask.bonafide._protocol import BonafideProtocol
from leap.bitmask.hooks import HookableService

from twisted.internet import defer
from twisted.logger import Logger


logger = Logger()
_preffix = get_path_prefix()


class BonafideService(HookableService):

    def __init__(self, basedir=None):
        if not basedir:
            basedir = os.path.join(_preffix, 'leap')
        self._basedir = os.path.expanduser(basedir)
        self._bonafide = BonafideProtocol()
        self.service_hooks = defaultdict(list)

        # XXX this is a quick hack to get a ref
        # to the latest authenticated user.
        self._active_user = None

    def startService(self):
        logger.debug('starting Bonafide Service')
        super(BonafideService, self).startService()

    # Commands

    def do_authenticate(self, username, password, autoconf=False):

        def notify_passphrase_entry(username, password):
            data = dict(username=username, password=password)
            self.trigger_hook('on_passphrase_entry', **data)

        def notify_bonafide_auth(result):
            if not result:
                msg = "authentication hook did not return anything"
                logger.debug(msg)
                raise RuntimeError(msg)

            token, uuid = result
            data = dict(username=username, token=token, uuid=uuid,
                        password=password)
            self.trigger_hook('on_bonafide_auth', **data)

            self._active_user = username
            return result

        # XXX I still have doubts from where it's best to trigger this.
        # We probably should wait for BOTH deferreds and
        # handle local and remote authentication success together
        # (and fail if either one fails). Going with fire-and-forget for
        # now, but needs needs improvement.

        notify_passphrase_entry(username, password)

        d = self._bonafide.do_authenticate(username, password, autoconf)
        d.addCallback(notify_bonafide_auth)
        d.addCallback(lambda response: {
            'srp_token': response[0], 'uuid': response[1]})
        return d

    def do_signup(self, username, password, invite=None, autoconf=False):
        d = self._bonafide.do_signup(
            username, password, invite=invite, autoconf=autoconf)
        d.addCallback(lambda response: {'signup': 'ok', 'user': response})
        return d

    def do_logout(self, username):
        if not username:
            username = self._active_user

        def reset_active(passthrough):
            self._active_user = None
            return passthrough

        data = dict(username=username)
        self.trigger_hook('on_bonafide_logout', **data)

        d = self._bonafide.do_logout(username)
        d.addCallback(reset_active)
        d.addCallback(lambda response: {'logout': 'ok'})
        return d

    def do_list_users(self):
        return self._bonafide.do_list_users()

    def do_change_password(self, username, current_password, new_password):
        def notify_passphrase_change(_):
            data = dict(username=username, password=new_password)
            self.trigger_hook('on_passphrase_change', **data)

        d = self._bonafide.do_change_password(username, current_password,
                                              new_password)
        d.addCallback(notify_passphrase_change)
        d.addCallback(lambda _: {'update': 'ok'})
        return d

    def do_provider_create(self, domain):
        return self._bonafide.do_get_provider(domain, autoconf=True)

    def do_provider_read(self, domain):
        return self._bonafide.do_get_provider(domain)

    def do_provider_delete(self, domain):
        return self._bonafide.do_provider_delete(domain)

    def do_provider_list(self, seeded=False):
        return self._bonafide.do_provider_list(seeded)

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
        user = self._active_user or '<none>'
        info = {'user': user}
        return defer.succeed(info)
