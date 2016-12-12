# -*- coding: utf-8 -*-
# service.py
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
Bitmask-core Service.
"""
import json
try:
    import resource
except ImportError:
    pass

from twisted.internet import reactor
from twisted.logger import Logger

from leap.bitmask import __version__
from leap.bitmask.core import configurable
from leap.bitmask.core import _zmq
from leap.bitmask.core import flags
from leap.bitmask.core import _session
from leap.bitmask.core.web.service import HTTPDispatcherService
from leap.common.events import server as event_server
# from leap.vpn import EIPService

logger = Logger()


backend = flags.BACKEND

if backend == 'default':
    from leap.bitmask.core import mail_services
    from leap.bitmask.bonafide.service import BonafideService
elif backend == 'dummy':
    from leap.bitmask.core.dummy import mail_services
    from leap.bitmask.core.dummy import BonafideService
else:
    raise RuntimeError('Backend not supported')


class BitmaskBackend(configurable.ConfigurableService):

    """
    The Bitmask Core Backend Service.
    Here is where the multiple service tree gets composed.
    This is passed to the command dispatcher.
    """

    def __init__(self, basedir=configurable.DEFAULT_BASEDIR):

        configurable.ConfigurableService.__init__(self, basedir)
        self.core_commands = BackendCommands(self)
        self.tokens = {}

        def enabled(service):
            return self.get_config('services', service, False, boolean=True)

        on_start = reactor.callWhenRunning

        on_start(self.init_events)
        on_start(self.init_bonafide)
        on_start(self.init_sessions)

        if enabled('mail'):
            on_start(self._init_mail_services)

        if enabled('eip'):
            on_start(self._init_eip)

        if enabled('zmq'):
            on_start(self._init_zmq)

        if enabled('web'):
            onion = enabled('onion')
            on_start(self._init_web, onion=onion)

        if enabled('websockets'):
            on_start(self._init_websockets)

    def init_events(self):
        event_server.ensure_server()

    def init_bonafide(self):
        bf = BonafideService(self.basedir)
        bf.setName('bonafide')
        bf.setServiceParent(self)
        # TODO ---- these hooks should be activated only if
        # (1) we have enabled that service
        # (2) provider offers this service
        bf.register_hook('on_passphrase_entry', listener='soledad')
        bf.register_hook('on_bonafide_auth', listener='soledad')
        bf.register_hook('on_passphrase_change', listener='soledad')
        bf.register_hook('on_bonafide_auth', listener='keymanager')
        bf.register_hook('on_bonafide_auth', listener='mail')
        bf.register_hook('on_bonafide_logout', listener='mail')

    def init_sessions(self):
        sessions = _session.SessionService(self.basedir, self.tokens)
        sessions.setServiceParent(self)

    def _start_child_service(self, name):
        logger.debug('starting backend child service: %s' % name)
        service = self.getServiceNamed(name)
        if service:
            service.startService()

    def _stop_child_service(self, name):
        logger.debug('stopping backend child service: %s' % name)
        service = self.getServiceNamed(name)
        if service:
            service.stopService()

    def _init_mail_services(self):
            self._init_soledad()
            self._init_keymanager()
            self._init_mail()

    def _start_mail_services(self):
        self._start_child_service('soledad')
        self._start_child_service('keymanager')
        self._start_child_service('mail')

    def _stop_mail_services(self):
        self._stop_child_service('mail')
        self._stop_child_service('keymanager')
        self._stop_child_service('soledad')

    def _init_soledad(self):
        service = mail_services.SoledadService
        sol = self._maybe_init_service(
            'soledad', service, self.basedir)
        if sol:
            sol.register_hook(
                'on_new_soledad_instance', listener='keymanager')

            # XXX this might not be the right place for hooking the sessions.
            # If we want to be offline, we need to authenticate them after
            # soledad. But this is not valid for the VPN case,
            # because we have not decided if soledad is required in that case
            # (seemingly not). If only VPN, then we have to return the token
            # from the SRP authentication.
            sol.register_hook(
                'on_new_soledad_instance', listener='sessions')

    def _init_keymanager(self):
        service = mail_services.KeymanagerService
        km = self._maybe_init_service(
            'keymanager', service, self.basedir)
        if km:
            km.register_hook('on_new_keymanager_instance', listener='mail')

    def _init_mail(self):
        service = mail_services.StandardMailService
        self._maybe_init_service('mail', service, self.basedir)

    def _init_eip(self):
        # FIXME -- land EIP into leap.vpn
        pass
        # self._maybe_init_service('eip', EIPService)

    def _init_zmq(self):
        zs = _zmq.ZMQServerService(self)
        zs.setServiceParent(self)

    def _init_web(self, onion=False):
        service = HTTPDispatcherService
        self._maybe_init_service('web', service, self, onion=onion)

    def _init_websockets(self):
        from leap.bitmask.core import websocket
        ws = websocket.WebSocketsDispatcherService(self)
        ws.setServiceParent(self)

    def _maybe_init_service(self, label, klass, *args, **kw):
        try:
            service = self.getServiceNamed(label)
        except KeyError:
            logger.debug("initializing service: %s" % label)
            service = klass(*args, **kw)
            service.setName(label)
            service.setServiceParent(self)
        return service

    def do_stats(self):
        return self.core_commands.do_stats()

    def do_status(self):
        return self.core_commands.do_status()

    def do_version(self):
        return self.core_commands.do_version()

    def do_stop(self):
        return self.core_commands.do_stop()

    # Service Toggling

    def do_enable_service(self, service):
        assert service in self.service_names
        self.set_config('services', service, 'True')

        if service == 'mail':
            self._init_mail_services()
            self._start_mail_services()

        elif service == 'eip':
            self._init_eip()

        elif service == 'zmq':
            self._init_zmq()

        elif service == 'web':
            self._init_web()

        return {'enabled': 'ok'}

    def do_disable_service(self, service):
        assert service in self.service_names

        if service == 'mail':
            self._stop_mail_services()

        self.set_config('services', service, 'False')
        return {'disabled': 'ok'}


class BackendCommands(object):

    """
    General Commands for the BitmaskBackend Core Service.
    """

    def __init__(self, core):
        self.core = core

    def do_status(self):
        # we may want to make this tuple a class member
        services = ('soledad', 'keymanager', 'mail', 'eip', 'web')

        status = {}
        for name in services:
            _status = 'stopped'
            try:
                if self.core.getServiceNamed(name).running:
                    _status = 'running'
            except KeyError:
                pass
            status[name] = _status
        status['backend'] = flags.BACKEND

        return json.dumps(status)

    def do_version(self):
        return {'version_core': __version__}

    def do_stats(self):
        print "DO STATS"
        logger.debug('BitmaskCore Service STATS')
        mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {'mem_usage': '%s MB' % (mem / 1024)}

    def do_stop(self):
        self.core.stopService()
        reactor.callLater(1, reactor.stop)
        return {'stop': 'ok'}
