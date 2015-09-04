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
import cookielib
import urllib

from twisted.internet import defer, reactor, protocol
from twisted.internet.ssl import Certificate
from twisted.web.client import Agent, CookieAgent, HTTPConnectionPool
from twisted.web.client import BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer
from twisted.python import log
from twisted.python.filepath import FilePath
from twisted.python import log
from zope.interface import implements

from leap.bonafide import srp_auth


class LeapSession(object):

    def __init__(self, credentials, api, provider_cert):
        # TODO check if an anonymous credentials is passed
        # TODO -- we could decorate some methods so that they
        # complain if we're not authenticated.

        self.username = credentials.username
        self.password = credentials.password

        self._api = api
        customPolicy = BrowserLikePolicyForHTTPS(
            Certificate.loadPEM(FilePath(provider_cert).getContent()))

        # BUG XXX See https://twistedmatrix.com/trac/ticket/7843
        pool = HTTPConnectionPool(reactor, persistent=False)
        agent = Agent(reactor, customPolicy, connectTimeout=30, pool=pool)
        cookiejar = cookielib.CookieJar()
        self._agent = CookieAgent(agent, cookiejar)

        self._srp_auth = srp_auth.SRPAuthMechanism()
        self._srp_user = None

    @defer.inlineCallbacks
    def authenticate(self):
        srpuser, A = self._srp_auth.initialize(
            self.username, self.password)
        self._srp_user = srpuser

        uri, method = self._api.get_uri_and_method('handshake')
        log.msg("%s to %s" % (method, uri))
        params = self._srp_auth.get_handshake_params(self.username, A)
        handshake = yield httpRequest(self._agent, uri, values=params,
                                      method=method)

        M = self._srp_auth.process_handshake(srpuser, handshake)
        uri, method = self._api.get_uri_and_method(
            'authenticate', login=self.username)
        log.msg("%s to %s" % (method, uri))
        params = self._srp_auth.get_authentication_params(M, A)
        auth = yield httpRequest(self._agent, uri, values=params,
                                 method=method)

        uuid, token, M2 = self._srp_auth.process_authentication(auth)
        self._srp_auth.verify_authentication(srpuser, M2)
        defer.succeed('ok')
        # XXX get_session_id??
        # XXX return defer.succeed

    def is_authenticated(self):
        if not self._srp_user:
            return False
        return self._srp_user.authenticated()


def httpRequest(agent, url, values={}, headers={}, method='POST'):
    headers['Content-Type'] = ['application/x-www-form-urlencoded']
    data = urllib.urlencode(values)
    d = agent.request(method, url, Headers(headers),
                      StringProducer(data) if data else None)

    def handle_response(response):
        if response.code == 204:
            d = defer.succeed('')
        else:
            class SimpleReceiver(protocol.Protocol):
                def __init__(s, d):
                    s.buf = ''
                    s.d = d

                def dataReceived(s, data):
                    print "----> handle response: GOT DATA"
                    s.buf += data

                def connectionLost(s, reason):
                    print "CONNECTION LOST ---", reason
                    # TODO: test if reason is twisted.web.client.ResponseDone,
                    # if not, do an errback
                    s.d.callback(s.buf)

            d = defer.Deferred()
            response.deliverBody(SimpleReceiver(d))
        return d

    d.addCallback(handle_response)
    return d


class StringProducer(object):

    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

if __name__ == "__main__":
    from leap.bonafide import provider
    from twisted.cred.credentials import UsernamePassword

    api = provider.LeapProviderApi('api.cdev.bitmask.net:4430', 1)
    credentials = UsernamePassword('test_deb_090', 'lalalala')

    cdev_pem = '/home/kali/.config/leap/providers/cdev.bitmask.net/keys/ca/cacert.pem'
    session = LeapSession(credentials, api, cdev_pem)

    def print_result(result):
        print "Auth OK"
        print "result"

    def cbShutDown(ignored):
        reactor.stop()

    d = session.authenticate()
    d.addCallback(print_result)
    d.addErrback(lambda f: log.err(f))
    d.addBoth(cbShutDown)
    reactor.run()
