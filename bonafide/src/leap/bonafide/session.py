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
from twisted.python import log

from leap.bonafide import _srp
from leap.bonafide import provider
from leap.bonafide._decorators import auth_required
from leap.bonafide._http import httpRequest, cookieAgentFactory

OK = 'ok'


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

        self.username = credentials.username
        self.password = credentials.password
        self._provider_cert = provider_cert
        self._api = api
        self._initialize_session()

    def _initialize_session(self):
        self._agent = cookieAgentFactory(self._provider_cert)
        self._srp_auth = _srp.SRPAuthMechanism()
        self._srp_signup = _srp.SRPSignupMechanism()
        self._srp_user = None
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
        if not self._srp_user:
            return False
        return self._srp_user.authenticated()

    @defer.inlineCallbacks
    def authenticate(self):
        srpuser, A = self._srp_auth.initialize(
            self.username, self.password)
        self._srp_user = srpuser

        uri = self._api.get_handshake_uri()
        met = self._api.get_handshake_method()
        log.msg("%s to %s" % (met, uri))
        params = self._srp_auth.get_handshake_params(self.username, A)

        handshake = yield self._request(self._agent, uri, values=params,
                                        method=met)

        M = self._srp_auth.process_handshake(srpuser, handshake)
        uri = self._api.get_authenticate_uri(login=self.username)
        met = self._api.get_authenticate_method()

        log.msg("%s to %s" % (met, uri))
        params = self._srp_auth.get_authentication_params(M, A)

        auth = yield self._request(self._agent, uri, values=params,
                                   method=met)

        uuid, token, M2 = self._srp_auth.process_authentication(auth)
        self._srp_auth.verify_authentication(srpuser, M2)

        self._uuid = uuid
        self._token = token
        defer.returnValue(OK)

    @auth_required
    @defer.inlineCallbacks
    def logout(self):
        uri = self._api.get_logout_uri()
        met = self._api.get_logout_method()
        auth = yield self._request(self._agent, uri, method=met)
        self.username = None
        self.password = None
        self._initialize_session()
        defer.returnValue(OK)

    # User certificates

    def get_vpn_cert(self):
        # TODO pass it to the provider object so that it can save it in the
        # right path.
        uri = self._api.get_vpn_cert_uri()
        met = self._api.get_vpn_cert_method()
        return self._request(self._agent, uri, method=met)

    @auth_required
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
    def signup(self, username, password):
        # XXX should check that it_IS_NOT_authenticated
        provider.validate_username(username)
        uri = self._api.get_signup_uri()
        met = self._api.get_signup_method()
        params = self._srp_signup.get_signup_params(
            username, password)

        signup = yield self._request(self._agent, uri, values=params,
                                     method=met)
        registered_user = self._srp_signup.process_signup(signup)
        self.username = username
        self.password = password
        defer.returnValue((OK, registered_user))

    @auth_required
    def update_user_record(self):
        pass


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
        print "[ERROR!]", failure.getErrorMessage()
        log.err(failure)

    d = session.authenticate()
    d.addCallback(print_result)
    d.addErrback(auth_eb)

    d.addCallback(lambda _: session.get_smtp_cert())
    #d.addCallback(lambda _: session.get_vpn_cert())
    d.addCallback(print_result)
    d.addErrback(auth_eb)

    d.addCallback(lambda _: session.logout())
    d.addErrback(auth_eb)
    d.addBoth(cbShutDown)
    reactor.run()
