# -*- coding: utf-8 -*-
# _web.py
# Copyright (C) 2016 LEAP Encryption Access Project
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
HTTP REST Dispatcher Service.
"""

import json
import os
import pkg_resources

from twisted.application import service

from twisted.internet import endpoints
from twisted.cred import portal, checkers, credentials, error as credError
from twisted.internet import reactor, defer
from twisted.logger import Logger
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory
from twisted.web.resource import IResource, Resource
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.static import File

from zope.interface import implementer

from leap.bitmask.util import here
from leap.bitmask.core.dispatcher import CommandDispatcher

try:
    import leap.bitmask_js
    HAS_WEB_UI = True
except ImportError:
    HAS_WEB_UI = False

try:
    import txtorcon
except Exception:
    pass

log = Logger()


class TokenCredentialFactory(BasicCredentialFactory):
    scheme = 'token'


@implementer(checkers.ICredentialsChecker)
class TokenDictChecker:

    credentialInterfaces = (credentials.IUsernamePassword,
                            credentials.IUsernameHashedPassword)

    def __init__(self, tokens):
        "tokens: a dict-like object mapping usernames to session-tokens"
        self.tokens = tokens 

    def requestAvatarId(self, credentials):
        username = credentials.username
        if username in self.tokens:
            if credentials.checkPassword(self.tokens[username]):
                return defer.succeed(username)
            else:
                return defer.fail(
                    credError.UnauthorizedLogin("Bad session token"))
        else:
            return defer.fail(
                credError.UnauthorizedLogin("No such user"))


@implementer(portal.IRealm)
class HttpPasswordRealm(object):

    def __init__(self, resource):
        self.resource = resource

    def requestAvatar(self, user, mind, *interfaces):
        if IResource in interfaces:
            # the resource is passed on regardless of user
            return (IResource, self.resource, lambda: None)
        raise NotImplementedError()


@implementer(IResource)
class WhitelistHTTPAuthSessionWrapper(HTTPAuthSessionWrapper):

    """
    Wrap a portal, enforcing supported header-based authentication schemes.
    It doesn't apply the enforcement to routes included in a whitelist.
    """

    # TODO extend this to inspect the data -- so that we pass a tuple
    # with the action

    whitelist = (None,)

    def __init__(self, *args, **kw):
        self.whitelist = kw.pop('whitelist', tuple())
        super(WhitelistHTTPAuthSessionWrapper, self).__init__(
            *args, **kw)

    def getChildWithDefault(self, path, request):
        if request.path in self.whitelist:
            return self
        return HTTPAuthSessionWrapper.getChildWithDefault(self, path, request)

    def render(self, request):
        if request.path in self.whitelist:
            _res = self._portal.realm.resource
            return _res.render(request)
        return HTTPAuthSessionWrapper.render(self, request)



def protectedResourceFactory(resource, passwords, whitelist):
    realm = HttpPasswordRealm(resource)
    # TODO this should have the per-site tokens.
    # can put it inside the API Resource object.
    checker = PasswordDictChecker(passwords)
    resource_portal = portal.Portal(realm, [checker])
    credentialFactory = TokenCredentialFactory('localhost')
    protected_resource = WhitelistHTTPAuthSessionWrapper(
        resource_portal, [credentialFactory],
        whitelist=whitelist)
    return protected_resource


class HTTPDispatcherService(service.Service):

    """
    A Dispatcher for BitmaskCore exposing a REST API.

    The API itself is served under the API/ route.

    If the package ``leap.bitmask_js`` is found in the import path, we'll serve
    the whole JS UI in the root resource too (under the ``public`` path).

    If that package cannot be found, we'll serve just the javascript wrapper
    around the REST API.
    """

    API_WHITELIST = (
        '/API/bonafide/user',
    )


    def __init__(self, core, port=7070, debug=False, onion=False):
        self._core = core
        self.port = port
        self.debug = debug
        self.onion = onion
        self.uri = ''

    def startService(self):
        # TODO refactor this, too long----------------------------------------
        if HAS_WEB_UI:
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask_js', 'public'))
            log.debug('webdir: %s' % webdir)
        else:
            log.warn('bitmask_js not found, serving bitmask.core ui')
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask.core', 'web'))
            jspath = os.path.join(
                here(), '..', '..', '..',
                'ui', 'app', 'lib', 'bitmask.js')
            jsapi = File(os.path.abspath(jspath))

        root = File(webdir)

        # TODO move this to the tests...
        DUMMY_PASS = {'user1': 'pass'}

        api = Api(CommandDispatcher(self._core))
        protected_api = protectedResourceFactory(
            api, DUMMY_PASS, self.API_WHITELIST)
        root.putChild(u'API', protected_api)

        if not HAS_WEB_UI:
            root.putChild('bitmask.js', jsapi)

        # TODO --- pass requestFactory for header authentication
        # so that we remove the setting of the cookie.

        # http://www.tsheffler.com/blog/2011/09/22/twisted-learning-about-cred-and-basicdigest-authentication/#Digest_Authentication
        factory = Site(root)
        self.site = factory

        if self.onion:
            try:
                import txtorcon
            except ImportError:
                log.error('onion is enabled, but could not find txtorcon')
                return
            self._start_onion_service(factory)
        else:
            interface = '127.0.0.1'
            endpoint = endpoints.TCP4ServerEndpoint(
                reactor, self.port, interface=interface)
            self.uri = 'https://%s:%s' % (interface, self.port)
            endpoint.listen(factory)

        # TODO this should be set in a callback to the listen call
        self.running = True

    def _start_onion_service(self, factory):

        def progress(percent, tag, message):
            bar = int(percent / 10)
            log.debug('[%s%s] %s' % ('#' * bar, '.' * (10 - bar), message))

        def setup_complete(port):
            port = txtorcon.IHiddenService(port)
            self.uri = "http://%s" % (port.getHost().onion_uri)
            log.info('I have set up a hidden service, advertised at: %s'
                     % self.uri)
            log.info('locally listening on %s' % port.local_address.getHost())

        def setup_failed(args):
            log.error('onion service setup FAILED: %r' % args)

        endpoint = endpoints.serverFromString(reactor, 'onion:80')
        txtorcon.IProgressProvider(endpoint).add_progress_listener(progress)
        d = endpoint.listen(factory)
        d.addCallback(setup_complete)
        d.addErrback(setup_failed)
        return d

    def stopService(self):
        self.site.stopFactory()
        self.listener.stopListening()
        self.running = False

    def do_status(self):
        status = 'running' if self.running else 'disabled'
        return {'web': status, 'uri': self.uri}


class Api(Resource):

    isLeaf = True

    def __init__(self, dispatcher):
        Resource.__init__(self)
        self.dispatcher = dispatcher

    def render_POST(self, request):
        command = request.uri.split('/')[2:]
        params = request.content.getvalue()
        if params:
            # json.loads returns unicode strings and the rest of the code
            # expects strings. This 'str(param)' conversion can be removed
            # if we move to python3
            for param in json.loads(params):
                command.append(str(param))

        d = self.dispatcher.dispatch(command)
        d.addCallback(self._write_response, request)
        return NOT_DONE_YET

    def _write_response(self, response, request):
        request.setHeader('Content-Type', 'application/json')
        request.write(response)
        request.finish()
