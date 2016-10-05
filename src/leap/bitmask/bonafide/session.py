# -*- coding: utf-8 -*-
# session.py
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
LEAP Session management.
"""
from twisted.internet import defer, reactor
from twisted.logger import Logger

from leap.bitmask.bonafide import _srp
from leap.bitmask.bonafide import provider
from leap.bitmask.bonafide._http import httpRequest, cookieAgentFactory

logger = Logger()

OK = 'ok'


def _auth_required(func):
    """
    Decorate a method so that it will not be called if the instance
    attribute `is_authenticated` does not evaluate to True.
    """
    def decorated(*args, **kwargs):
        instance = args[0]
        allowed = getattr(instance, 'is_authenticated')
        if not allowed:
            raise RuntimeError('This method requires authentication')
        return func(*args, **kwargs)
    return decorated


class Session(object):

    def __init__(self, credentials, api, provider_cert):
        # TODO check if an anonymous credentials is passed.
        # TODO move provider_cert to api object.
        # On creation, it should be able to retrieve all the info it needs
        # (calling bootstrap).
        # TODO could get a "provider" object instead.
        # this provider can have an api attribute,
        # and a "autoconfig" attribute passed on initialization.
        # TODO get a file-descriptor for password if not in credentials
        # TODO merge self._request with config.Provider._http_request ?

        self.username = credentials.username
        self.password = credentials.password
        self._provider_cert = provider_cert
        self._api = api
        self._initialize_session()

    def _initialize_session(self):
        self._agent = cookieAgentFactory(self._provider_cert)
        username = self.username or ''
        password = self.password or ''
        self._srp_auth = _srp.SRPAuthMechanism(username, password)
        self._srp_signup = _srp.SRPSignupMechanism()
        self._srp_password = _srp.SRPPasswordChangeMechanism()
        self._token = None
        self._uuid = None

    # Session

    @property
    def token(self):
        return self._token

    @property
    def uuid(self):
        return self._uuid

    @property
    def is_authenticated(self):
        return self._srp_auth.srp_user.authenticated()

    @defer.inlineCallbacks
    def authenticate(self):
        uri = self._api.get_handshake_uri()
        met = self._api.get_handshake_method()
        logger.debug("%s to %s" % (met, uri))
        params = self._srp_auth.get_handshake_params()

        handshake = yield self._request(self._agent, uri, values=params,
                                        method=met)

        self._srp_auth.process_handshake(handshake)
        uri = self._api.get_authenticate_uri(login=self.username)
        met = self._api.get_authenticate_method()

        logger.debug("%s to %s" % (met, uri))
        params = self._srp_auth.get_authentication_params()

        auth = yield self._request(self._agent, uri, values=params,
                                   method=met)

        uuid, token = self._srp_auth.process_authentication(auth)
        self._srp_auth.verify_authentication()

        self._uuid = uuid
        self._token = token
        defer.returnValue(OK)

    @_auth_required
    @defer.inlineCallbacks
    def logout(self):
        uri = self._api.get_logout_uri()
        met = self._api.get_logout_method()
        auth = yield self._request(self._agent, uri, method=met)
        print 'AUTH', auth
        print 'resetting user/pass'
        self.username = None
        self.password = None
        self._initialize_session()
        defer.returnValue(OK)

    @_auth_required
    @defer.inlineCallbacks
    def change_password(self, password):
        uri = self._api.get_update_user_uri(uid=self._uuid)
        met = self._api.get_update_user_method()
        params = self._srp_password.get_password_params(
            self.username, password)
        update = yield self._request(self._agent, uri, values=params,
                                     method=met)
        self.password = password
        self._srp_auth = _srp.SRPAuthMechanism(self.username, password)
        defer.returnValue(OK)

    # User certificates

    def get_vpn_cert(self):
        # TODO pass it to the provider object so that it can save it in the
        # right path.
        uri = self._api.get_vpn_cert_uri()
        met = self._api.get_vpn_cert_method()
        return self._request(self._agent, uri, method=met)

    @_auth_required
    def get_smtp_cert(self):
        # TODO pass it to the provider object so that it can save it in the
        # right path.
        uri = self._api.get_smtp_cert_uri()
        met = self._api.get_smtp_cert_method()
        print met, "to", uri
        return self._request(self._agent, uri, method=met)

    def _request(self, *args, **kw):
        kw['token'] = self._token
        return httpRequest(*args, **kw)

    # User management

    @defer.inlineCallbacks
    def signup(self, username, password, invite=None):
        # XXX should check that it_IS_NOT_authenticated
        provider.validate_username(username)
        uri = self._api.get_signup_uri()
        met = self._api.get_signup_method()
        params = self._srp_signup.get_signup_params(
            username, password, invite)

        signup = yield self._request(self._agent, uri, values=params,
                                     method=met)
        registered_user = self._srp_signup.process_signup(signup)
        self.username = username
        self.password = password
        defer.returnValue((OK, registered_user))

    @_auth_required
    def update_user_record(self):
        # FIXME to be implemented
        pass

    # Authentication-protected configuration

    @defer.inlineCallbacks
    def fetch_provider_configs(self, uri, path):
        config = yield self._request(self._agent, uri)
        with open(path, 'w') as cf:
            cf.write(config)
        defer.returnValue('ok')


if __name__ == "__main__":
    import os
    import sys
    from twisted.cred.credentials import UsernamePassword

    if len(sys.argv) != 4:
        print "Usage:", sys.argv[0], "provider", "username", "password"
        sys.exit()
    _provider, username, password = sys.argv[1], sys.argv[2], sys.argv[3]
    api = provider.Api('https://api.%s:4430' % _provider)
    credentials = UsernamePassword(username, password)
    cdev_pem = os.path.expanduser(
        '~/.config/leap/providers/%s/keys/ca/cacert.pem' % _provider)
    session = Session(credentials, api, cdev_pem)

    def print_result(result):
        print result
        return result

    def cbShutDown(ignored):
        reactor.stop()

    def auth_eb(failure):
        logger.error(failure)

    d = session.authenticate()
    d.addCallback(print_result)
    d.addErrback(auth_eb)

    d.addCallback(lambda _: session.get_smtp_cert())
    # d.addCallback(lambda _: session.get_vpn_cert())
    d.addCallback(print_result)
    d.addErrback(auth_eb)

    d.addCallback(lambda _: session.logout())
    d.addErrback(auth_eb)
    d.addBoth(cbShutDown)
    reactor.run()
