# -*- coding: utf-8 -*-
# service.py
# Copyright (C) 2016 LEAP Encryption Acess Project
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

import os
import pkg_resources

from twisted.application import service
from twisted.logger import Logger
from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.static import File

from leap.bitmask.core.dispatcher import CommandDispatcher
from leap.bitmask.core.web import HAS_WEB_UI
from leap.bitmask.core.web.api import Api
from leap.bitmask.core.web._auth import protectedResourceFactory
from leap.bitmask.util import here

try:
    import txtorcon
except ImportError:
    pass


log = Logger()


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
        '/API/core/version',
        '/API/core/stats',
        '/API/bonafide/user/create',
        '/API/bonafide/user/authenticate',
        '/API/bonafide/provider/list',
        '/API/bonafide/provider/create',
        '/API/bonafide/provider/read',
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
                pkg_resources.resource_filename(
                    'leap.bitmask.core.web', 'static'))
            jspath = os.path.join(
                here(), '..', '..', '..',
                'ui', 'app', 'lib', 'bitmask.js')
            jsapi = File(os.path.abspath(jspath))

        api = Api(CommandDispatcher(self._core))
        protected_api = protectedResourceFactory(
            api, self._core.tokens, self.API_WHITELIST)

        root = File(webdir)
        root.putChild(u'API', protected_api)
        if not HAS_WEB_UI:
            root.putChild('bitmask.js', jsapi)

        factory = Site(root)
        self.site = factory

        if self.onion and _has_txtorcon():
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


def _has_txtorcon():
    try:
        import txtorcon
        txtorcon
    except ImportError:
        log.error('onion is enabled, but could not find txtorcon')
        return False
    return True
