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
from leap.common.config import get_path_prefix

from twisted.cred.credentials import UsernamePassword
from twisted.internet.defer import fail
from twisted.python import log


# TODO [ ] enable-disable services
# TODO [ ] read provider info

COMMANDS = 'signup', 'authenticate', 'logout', 'stats'
_preffix = get_path_prefix()


class BonafideProtocol(object):
    """
    Expose the protocol that interacts with the Bonafide Service API.
    """

    _apis = defaultdict(None)
    _sessions = defaultdict(None)

    def _get_api(self, provider_id):
        # TODO should get deferred
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
        provider_pem = _get_provider_ca_path(provider_id)
        session = Session(credentials, api, provider_pem)
        self._sessions[full_id] = session
        return session

    # Service public methods

    def do_signup(self, full_id, password):
        log.msg('SIGNUP for %s' % full_id)
        _, provider_id = config.get_username_and_provider(full_id)

        provider = config.Provider(provider_id)
        d = provider.callWhenReady(self._do_signup, full_id, password)
        return d

    def _do_signup(self, full_id, password):

        # XXX check it's unauthenticated
        def return_user(result, _session):
            return_code, user = result
            if return_code == OK:
                return user

        username, _ = config.get_username_and_provider(full_id)
        # XXX get deferred?
        session = self._get_session(full_id, password)
        d = session.signup(username, password)
        d.addCallback(return_user, session)
        return d

    def do_authenticate(self, full_id, password):
        _, provider_id = config.get_username_and_provider(full_id)

        provider = config.Provider(provider_id)

        def maybe_finish_provider_bootstrap(result, provider):
            session = self._get_session(full_id, password)
            d = provider.download_services_config_with_auth(session)
            d.addCallback(lambda _: result)
            return d

        d = provider.callWhenMainConfigReady(
            self._do_authenticate, full_id, password)
        d.addCallback(maybe_finish_provider_bootstrap, provider)
        return d

    def _do_authenticate(self, full_id, password):

        def return_token_and_uuid(result, _session):
            if result == OK:
                # TODO -- turn this into JSON response
                return str(_session.token), str(_session.uuid)

        log.msg('AUTH for %s' % full_id)

        # XXX get deferred?
        session = self._get_session(full_id, password)
        d = session.authenticate()
        d.addCallback(return_token_and_uuid, session)
        return d

    def do_logout(self, full_id, password):
        # XXX use the AVATAR here
        log.msg('LOGOUT for %s' % full_id)
        session = self._get_session(full_id)
        if not session.is_authenticated:
            return fail(RuntimeError("There is no session for such user"))

        d = session.logout()
        d.addCallback(lambda _: self._sessions.pop(full_id))
        d.addCallback(lambda _: '%s logged out' % full_id)
        return d

    def do_get_smtp_cert(self, full_id):
        session = self._get_session(full_id)
        d = session.get_smtp_cert()
        return d

    def do_get_vpn_cert(self):
        # FIXME to be implemented
        pass

    def do_update_user(self):
        # FIXME to be implemented
        pass

    def do_stats(self):
        log.msg('Calculating Bonafide Service STATS')
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {'sessions': len(self._sessions),
                'mem': '%s KB' % (mem / 1024)}


def _get_provider_ca_path(provider_id):
    return os.path.join(
        _preffix, 'leap', 'providers', provider_id, 'keys', 'ca', 'cacert.pem')
