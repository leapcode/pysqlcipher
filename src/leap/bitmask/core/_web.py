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

from twisted.internet import reactor
from twisted.application import service

from twisted.internet import endpoints
from twisted.web.resource import Resource
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.static import File
from twisted.logger import Logger

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


class HTTPDispatcherService(service.Service):

    """
    A Dispatcher for BitmaskCore exposing a REST API.
    If the leap.bitmask_js package is available in the search path, it will
    serve the UI under this same service too.
    """

    def __init__(self, core, port=7070, debug=False, onion=False):
        self._core = core
        self.port = port
        self.debug = debug
        self.onion = onion
        self.uri = ''

    def startService(self):
        if HAS_WEB_UI:
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask_js', 'public'))
            log.debug('webdir: %s' % webdir)
        else:
            log.warn('bitmask_js not found, serving bitmask.core ui')
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask.core', 'web'))
        root = File(webdir)

        api = Api(CommandDispatcher(self._core))
        root.putChild(u'API', api)

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
