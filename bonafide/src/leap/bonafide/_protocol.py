# -*- coding: utf-8 -*-
# _protocol.py
# Copyright (C) 2014-2015 LEAP
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
Bonafide protocol.
"""
import os
import resource
from collections import defaultdict

from leap.bonafide import config
from leap.bonafide import provider
from leap.bonafide.session import Session, OK

from twisted.cred.credentials import UsernamePassword
from twisted.internet.defer import fail
from twisted.python import log


# TODO [ ] enable-disable services
# TODO [ ] read provider info

COMMANDS = 'signup', 'authenticate', 'logout', 'stats'


class BonafideProtocol(object):
    """
    Expose the protocol that interacts with the Bonafide Service API.
    """

    _apis = defaultdict(None)
    _sessions = defaultdict(None)

    def _get_api(self, provider_id):
        if provider_id in self._apis:
            return self._apis[provider_id]

        # XXX lookup the provider config instead
        # TODO defer the autoconfig for the provider if needed...
        api = provider.Api('https://api.%s:4430' % provider_id)
        self._apis[provider_id] = api
        return api

    def _get_session(self, full_id, password=""):
        if full_id in self._sessions:
            return self._sessions[full_id]

        # TODO if password/username null, then pass AnonymousCreds
        # TODO use twisted.cred instead
        username, provider_id = config.get_username_and_provider(full_id)
        credentials = UsernamePassword(username, password)
        api = self._get_api(provider_id)
        cdev_pem = os.path.expanduser(
            '~/.config/leap/providers/%s/keys/ca/cacert.pem' %
            provider_id)
        session = Session(credentials, api, cdev_pem)
        self._sessions[full_id] = session
        return session

    # Service public methods

    def do_signup(self, full_id, password):
        # XXX check it's unauthenticated
        def return_user(result, _session):
            return_code, user = result
            if return_code == OK:
                return user

        log.msg('SIGNUP for %s' % full_id)
        session = self._get_session(full_id, password)
        username, provider_id = config.get_username_and_provider(full_id)

        d = session.signup(username, password)
        d.addCallback(return_user, session)
        return d

    def do_authenticate(self, full_id, password):
        def return_token(result, _session):
            if result == OK:
                return str(_session.token)

        log.msg('AUTH for %s' % full_id)
        session = self._get_session(full_id, password)
        d = session.authenticate()
        d.addCallback(return_token, session)
        return d

    def do_logout(self, full_id, password):
        # XXX use the AVATAR here
        log.msg('LOGOUT for %s' % full_id)
        session = self._get_session(full_id)
        if not session.is_authenticated:
            return fail(RuntimeError("There is no session for such user"))
        try:
            d = session.logout()
        except Exception as exc:
            log.err(exc)
            return fail(exc)

        d.addCallback(lambda _: self._sessions.pop(full_id))
        d.addCallback(lambda _: '%s logged out' % full_id)
        return d

    def do_stats(self):
        log.msg('Calculating Bonafide STATS')
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return '[+] Bonafide service: [%s sessions] [Mem usage: %s KB]' % (
            len(self._sessions), mem / 1024)

    def do_get_vpn_cert(self):
        pass

    def do_get_smtp_cert(self):
        pass

    def do_update_user(self):
        pass
