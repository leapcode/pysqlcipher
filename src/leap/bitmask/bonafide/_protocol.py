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
from collections import defaultdict

try:
    import resource
except ImportError:
    pass

from leap.bitmask.bonafide import config
from leap.bitmask.bonafide.provider import Api
from leap.bitmask.bonafide.session import Session, OK
from leap.common.config import get_path_prefix

from twisted.cred.credentials import UsernamePassword
from twisted.internet.defer import fail
from twisted.logger import Logger


# TODO [ ] enable-disable services
# TODO [ ] read provider info

logger = Logger()


COMMANDS = 'signup', 'authenticate', 'logout', 'stats'
_preffix = get_path_prefix()


class BonafideProtocol(object):
    """
    Expose the protocol that interacts with the Bonafide Service API.
    """

    _apis = defaultdict(None)
    _sessions = defaultdict(None)

    def _get_api(self, provider):
        # TODO should get deferred
        if provider.domain in self._apis:
            return self._apis[provider.domain]

        # TODO defer the autoconfig for the provider if needed...
        api = Api(provider.api_uri, provider.version)
        self._apis[provider.domain] = api
        return api

    def _get_session(self, provider, full_id, password=""):
        if full_id in self._sessions:
            return self._sessions[full_id]

        # TODO if password/username null, then pass AnonymousCreds
        # TODO use twisted.cred instead
        username, provider_id = config.get_username_and_provider(full_id)
        credentials = UsernamePassword(username, password)
        api = self._get_api(provider)
        provider_pem = _get_provider_ca_path(provider_id)
        session = Session(credentials, api, provider_pem)
        self._sessions[full_id] = session
        return session

    def _del_session_errback(self, failure, full_id):
        if full_id in self._sessions:
            del self._sessions[full_id]
        return failure

    # Service public methods

    def do_signup(self, full_id, password, invite=None, autoconf=False):
        logger.debug('SIGNUP for %s' % full_id)
        _, provider_id = config.get_username_and_provider(full_id)

        provider = config.Provider(provider_id, autoconf=autoconf)
        d = provider.callWhenReady(
            self._do_signup, provider, full_id, password, invite)
        return d

    def _do_signup(self, provider, full_id, password, invite):

        # XXX check it's unauthenticated
        def return_user(result, _session):
            return_code, user = result
            if return_code == OK:
                return user

        username, _ = config.get_username_and_provider(full_id)
        # XXX get deferred?
        session = self._get_session(provider, full_id, password)
        d = session.signup(username, password, invite)
        d.addCallback(return_user, session)
        d.addErrback(self._del_session_errback, full_id)
        return d

    def do_authenticate(self, full_id, password, autoconf=False):
        _, provider_id = config.get_username_and_provider(full_id)

        provider = config.Provider(provider_id, autoconf=autoconf)

        def maybe_finish_provider_bootstrap(result, provider):
            session = self._get_session(provider, full_id, password)
            d = provider.download_services_config_with_auth(session)
            d.addCallback(lambda _: result)
            return d

        d = provider.callWhenReady(
            self._do_authenticate, provider, full_id, password)
        d.addCallback(maybe_finish_provider_bootstrap, provider)
        return d

    def _do_authenticate(self, provider, full_id, password):

        def return_token_and_uuid(result, _session):
            if result == OK:
                # TODO -- turn this into JSON response
                return str(_session.token), str(_session.uuid)

        logger.debug('AUTH for %s' % full_id)

        # XXX get deferred?
        session = self._get_session(provider, full_id, password)
        d = session.authenticate()
        d.addCallback(return_token_and_uuid, session)
        d.addErrback(self._del_session_errback, full_id)
        return d

    def do_logout(self, full_id):
        # XXX use the AVATAR here
        logger.debug('LOGOUT for %s' % full_id)
        if (full_id not in self._sessions or
                not self._sessions[full_id].is_authenticated):
            return fail(RuntimeError("There is no session for such user"))
        session = self._sessions[full_id]

        d = session.logout()
        d.addCallback(lambda _: self._sessions.pop(full_id))
        d.addCallback(lambda _: '%s logged out' % full_id)
        return d

    def do_list_users(self):
        users = []
        for user, session in self._sessions.items():
            users.append({'userid': user,
                          'authenticated': session.is_authenticated})
        return users

    def do_change_password(self, full_id, current_password, new_password):
        logger.debug('change password for %s' % full_id)
        if (full_id not in self._sessions or
                not self._sessions[full_id].is_authenticated):
            return fail(RuntimeError("There is no session for such user"))
        session = self._sessions[full_id]

        if current_password != session.password:
            return fail(RuntimeError("The current password is not valid"))

        return session.change_password(new_password)

    def do_get_provider(self, provider_id, autoconf=False):
        provider = config.Provider(provider_id, autoconf=autoconf)
        return provider.callWhenMainConfigReady(provider.config)

    def do_provider_delete(self, provider_id):
        return config.delete_provider(provider_id)

    def do_provider_list(self, seeded=False):
        # TODO: seeded, we don't have pinned providers yet
        providers = config.list_providers()
        return [{"domain": p} for p in providers]

    def do_get_smtp_cert(self, full_id):
        if (full_id not in self._sessions or
                not self._sessions[full_id].is_authenticated):
            return fail(RuntimeError("There is no session for such user"))
        d = self._sessions[full_id].get_smtp_cert()
        return d

    def do_get_vpn_cert(self):
        # FIXME to be implemented
        pass

    def do_update_user(self):
        # FIXME to be implemented
        pass

    def do_stats(self):
        logger.debug('calculating Bonafide Service STATS')
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {'sessions': len(self._sessions),
                'mem': '%s KB' % (mem / 1024)}


def _get_provider_ca_path(provider_id):
    return os.path.join(
        _preffix, 'leap', 'providers', provider_id, 'keys', 'ca', 'cacert.pem')
