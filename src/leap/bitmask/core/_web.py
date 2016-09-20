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

from twisted.web.resource import Resource
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.static import File
from twisted.python import log

from leap.bitmask.core.dispatcher import CommandDispatcher

try:
    import leap.bitmask_www
    HAS_WEB_UI = True
except ImportError:
    HAS_WEB_UI = False


class HTTPDispatcherService(service.Service):

    """
    A Dispatcher for BitmaskCore exposing a REST API.
    """

    def __init__(self, core, port=7070, debug=False):
        self._core = core
        self.port = port
        self.debug = debug

    def startService(self):
        if HAS_WEB_UI:
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask_www', 'public'))
        else:
            log.msg('leap.bitmask_www not found, serving bitmask.core web ui')
            webdir = os.path.abspath(
                pkg_resources.resource_filename('leap.bitmask.core', 'web'))
        root = File(webdir)

        api = Api(CommandDispatcher(self._core))
        root.putChild(u'API', api)

        site = Site(root)
        self.site = site

        # TODO use endpoints instead
        self.listener = reactor.listenTCP(self.port, site,
                                          interface='127.0.0.1')
        self.running = True

    def stopService(self):
        self.site.stopFactory()
        self.listener.stopListening()
        self.running = False

    def do_status(self):
        status = 'running' if self.running else 'disabled'
        return {'web': status}


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
