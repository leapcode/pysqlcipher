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

from leap.bonafide import srp_auth
from leap.bonafide._decorators import auth_required
from leap.bonafide._http import httpRequest, cookieAgentFactory


class LeapSession(object):

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
        self._api = api

        self._agent = cookieAgentFactory(provider_cert)
        self._srp_auth = srp_auth.SRPAuthMechanism()
        self._srp_user = None
        self._token = None
        self._uuid = None

    @defer.inlineCallbacks
    def authenticate(self):
        srpuser, A = self._srp_auth.initialize(
            self.username, self.password)
        self._srp_user = srpuser

        uri, method = self._api.get_uri_and_method('handshake')
        log.msg("%s to %s" % (method, uri))
        params = self._srp_auth.get_handshake_params(self.username, A)

        handshake = yield self._request(self._agent, uri, values=params,
                                        method=method)

        M = self._srp_auth.process_handshake(srpuser, handshake)
        uri, method = self._api.get_uri_and_method(
            'authenticate', login=self.username)
        log.msg("%s to %s" % (method, uri))
        params = self._srp_auth.get_authentication_params(M, A)

        auth = yield self._request(self._agent, uri, values=params,
                                   method=method)

        uuid, token, M2 = self._srp_auth.process_authentication(auth)
        self._srp_auth.verify_authentication(srpuser, M2)

        self._uuid = uuid
        self._token = token
        defer.returnValue('[OK] Credentials Authenticated through SRP')

    @auth_required
    def logout(self):
        print "Should logout..."

    @auth_required
    def get_smtp_cert(self):
        # TODO pass it to the provider object so that it can save it in the
        # right path.
        uri, method = self._api.get_uri_and_method('get_smtp_cert')
        print method, "to", uri
        return self._request(self._agent, uri, method=method)

    @property
    def is_authenticated(self):
        if not self._srp_user:
            return False
        return self._srp_user.authenticated()

    def _request(self, *args, **kw):
        kw['token'] = self._token
        return httpRequest(*args, **kw)


if __name__ == "__main__":
    from leap.bonafide import provider
    from twisted.cred.credentials import UsernamePassword

    api = provider.LeapProviderApi('api.cdev.bitmask.net:4430', 1)
    credentials = UsernamePassword('test_deb_090', 'lalalala')

    cdev_pem = '/home/kali/.config/leap/providers/cdev.bitmask.net/keys/ca/cacert.pem'
    session = LeapSession(credentials, api, cdev_pem)

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
    d.addCallback(print_result)
    d.addErrback(auth_eb)
    d.addCallback(lambda _: session.logout())
    d.addBoth(cbShutDown)
    reactor.run()
