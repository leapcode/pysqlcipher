# -*- coding: utf-8 -*-
# mail_services.py
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
Mail services.

This is quite moving work still.
This should be moved to the different submodules when it stabilizes.
"""
import json
import os
import shutil
import tempfile
from collections import defaultdict
from collections import namedtuple

from twisted.application import service
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet import task
from twisted.logger import Logger

from leap.common.files import check_and_fix_urw_only
from leap.bitmask.hooks import HookableService
from leap.bitmask.bonafide import config
from leap.bitmask.keymanager import KeyManager
from leap.bitmask.keymanager.errors import KeyNotFound
from leap.bitmask.keymanager.validation import ValidationLevels
from leap.bitmask.mail.constants import INBOX_NAME
from leap.bitmask.mail.mail import Account
from leap.bitmask.mail.imap import service as imap_service
from leap.bitmask.mail.smtp import service as smtp_service
from leap.bitmask.mail.incoming.service import IncomingMail
from leap.bitmask.mail.incoming.service import INCOMING_CHECK_PERIOD
from leap.bitmask.util import get_gpg_bin_path
from leap.soledad.client.api import Soledad

from leap.bitmask.core.uuid_map import UserMap
from leap.bitmask.core.configurable import DEFAULT_BASEDIR


logger = Logger()


class Container(object):

    def __init__(self, service=None):
        self._instances = defaultdict(None)
        if service is not None:
            self.service = service

    def get_instance(self, key):
        return self._instances.get(key, None)

    def add_instance(self, key, data):
        self._instances[key] = data


class ImproperlyConfigured(Exception):
    pass


class SoledadContainer(Container):

    def __init__(self, service=None, basedir=DEFAULT_BASEDIR):
        self._basedir = os.path.expanduser(basedir)
        self._usermap = UserMap()
        super(SoledadContainer, self).__init__(service=service)

    def add_instance(self, userid, passphrase, uuid=None, token=None):

        if not uuid:
            bootstrapped_uuid = self._usermap.lookup_uuid(userid, passphrase)
            uuid = bootstrapped_uuid
            if not uuid:
                return
        else:
            self._usermap.add(userid, uuid, passphrase)

        user, provider = userid.split('@')

        soledad_path = os.path.join(self._basedir, 'soledad')
        soledad_url = _get_soledad_uri(self._basedir, provider)
        cert_path = _get_ca_cert_path(self._basedir, provider)

        soledad = self._create_soledad_instance(
            uuid, passphrase, soledad_path, soledad_url,
            cert_path, token)

        super(SoledadContainer, self).add_instance(userid, soledad)

        data = {'user': userid, 'uuid': uuid, 'token': token,
                'soledad': soledad}
        self.service.trigger_hook('on_new_soledad_instance', **data)

    def _create_soledad_instance(self, uuid, passphrase, soledad_path,
                                 server_url, cert_file, token):
        # setup soledad info
        secrets_path = os.path.join(soledad_path, '%s.secret' % uuid)
        local_db_path = os.path.join(soledad_path, '%s.db' % uuid)

        if token is None:
            syncable = False
            token = ''
        else:
            syncable = True

        return Soledad(
            uuid,
            unicode(passphrase),
            secrets_path=secrets_path,
            local_db_path=local_db_path,
            server_url=server_url,
            cert_file=cert_file,
            auth_token=token,
            syncable=syncable)

    def set_remote_auth_token(self, userid, token):
        self.get_instance(userid).token = token

    def set_syncable(self, userid, state):
        # TODO should check that there's a token!
        self.get_instance(userid).set_syncable(bool(state))

    def sync(self, userid):
        self.get_instance(userid).sync()


def _get_provider_from_full_userid(userid):
    _, provider_id = config.get_username_and_provider(userid)
    # TODO -- this autoconf should be passed from the
    # command flag. workaround to get cli workinf for now.
    return config.Provider(provider_id, autoconf=True)


def is_service_ready(service, provider):
    """
    Returns True when the following conditions are met:
       - Provider offers that service.
       - We have the config files for the service.
       - The service is enabled.
    """
    has_service = provider.offers_service(service)
    has_config = provider.has_config_for_service(service)
    is_enabled = provider.is_service_enabled(service)
    return has_service and has_config and is_enabled


class SoledadService(HookableService):

    def __init__(self, basedir):
        service.Service.__init__(self)
        self._basedir = basedir

    def startService(self):
        logger.info('starting Soledad Service')
        self._container = SoledadContainer(service=self)
        super(SoledadService, self).startService()

    # hooks

    def hook_on_passphrase_entry(self, **kw):
        userid = kw.get('username')
        provider = _get_provider_from_full_userid(userid)
        provider.callWhenReady(self._hook_on_passphrase_entry, provider, **kw)

    def _hook_on_passphrase_entry(self, provider, **kw):
        if is_service_ready('mx', provider):
            userid = kw.get('username')
            password = kw.get('password')
            uuid = kw.get('uuid')
            container = self._container
            logger.debug("on_passphrase_entry: "
                         "New Soledad Instance: %s" % userid)
            if not container.get_instance(userid):
                container.add_instance(userid, password, uuid=uuid, token=None)
        else:
            logger.debug('service MX is not ready...')

    def hook_on_bonafide_auth(self, **kw):
        userid = kw['username']
        provider = _get_provider_from_full_userid(userid)
        provider.callWhenReady(self._hook_on_bonafide_auth, provider, **kw)

    def _hook_on_bonafide_auth(self, provider, **kw):
        if provider.offers_service('mx'):
            userid = kw['username']
            password = kw['password']
            token = kw['token']
            uuid = kw['uuid']

            container = self._container
            if container.get_instance(userid):
                logger.debug("passing a new SRP Token to Soledad: %s" % userid)
                container.set_remote_auth_token(userid, token)
                container.set_syncable(userid, True)
            else:
                logger.debug("adding a new Soledad Instance: %s" % userid)
                container.add_instance(
                    userid, password, uuid=uuid, token=token)

    def hook_on_passphrase_change(self, **kw):
        # TODO: if bitmask stops before this hook being executed bonafide and
        #       soledad will end up with different passwords
        #       https://leap.se/code/issues/8489
        userid = kw['username']
        password = kw['password']
        soledad = self._container.get_instance(userid)
        if soledad is not None:
            logger.info("Change soledad passphrase for %s" % userid)
            soledad.change_passphrase(unicode(password))


class KeymanagerContainer(Container):

    def __init__(self, service=None, basedir=DEFAULT_BASEDIR):
        self._basedir = os.path.expanduser(basedir)
        super(KeymanagerContainer, self).__init__(service=service)

    def add_instance(self, userid, token, uuid, soledad):
        logger.debug("adding Keymanager instance for: %s" % userid)
        keymanager = self._create_keymanager_instance(
            userid, token, uuid, soledad)
        super(KeymanagerContainer, self).add_instance(userid, keymanager)
        d = self._get_or_generate_keys(keymanager, userid)
        d.addCallback(self._on_keymanager_ready_cb, userid, soledad)
        return d

    def set_remote_auth_token(self, userid, token):
        self.get_instance(userid).token = token

    def _on_keymanager_ready_cb(self, keymanager, userid, soledad):
        data = {'userid': userid, 'soledad': soledad, 'keymanager': keymanager}
        self.service.trigger_hook('on_new_keymanager_instance', **data)

    def _get_or_generate_keys(self, keymanager, userid):

        def _get_key(_):
            logger.info("looking up private key for %s" % userid)
            return keymanager.get_key(userid, private=True, fetch_remote=False)

        def _found_key(key):
            logger.info("found key: %r" % key)

        def _if_not_found_generate(failure):
            failure.trap(KeyNotFound)
            logger.info("key not found, generating key for %s" % (userid,))
            d = keymanager.gen_key()
            d.addCallbacks(_send_key, _log_key_error("generating"))
            return d

        def _send_key(ignored):
            # ----------------------------------------------------------------
            # It might be the case that we have generated a key-pair
            # but this hasn't been successfully uploaded. How do we know that?
            # XXX Should this be a method of bonafide instead?
            # -----------------------------------------------------------------
            logger.info("key generated for %s" % userid)

            if not keymanager.token:
                logger.debug(
                    "token not available, scheduling "
                    "a new key sending attempt...")
                return task.deferLater(reactor, 5, _send_key, None)

            logger.info("sending public key to server")
            d = keymanager.send_key()
            d.addCallbacks(
                lambda _: logger.info("key sent to server"),
                _log_key_error("sending"))
            return d

        def _log_key_error(step):
            def log_error(failure):
                logger.error("Error while %s key!" % step)
                logger.error(failure)
                return failure
            return log_error

        def _sync_if_never_synced(ever_synced):
            if ever_synced:
                logger.debug("soledad has synced in the past")
                return defer.succeed(None)

            logger.debug("soledad has never synced")

            if not keymanager.token:
                logger.debug("no token to sync now, scheduling a new check")
                d = task.deferLater(reactor, 5, keymanager.ever_synced)
                d.addCallback(_sync_if_never_synced)
                return d

            logger.debug("syncing soledad for the first time...")
            return keymanager._soledad.sync()

        logger.debug("checking if soledad has ever synced...")
        d = keymanager.ever_synced()
        d.addCallback(_sync_if_never_synced)
        d.addCallback(_get_key)
        d.addCallbacks(_found_key, _if_not_found_generate)
        d.addCallback(lambda _: keymanager)
        return d

    def _create_keymanager_instance(self, userid, token, uuid, soledad):
        user, provider = userid.split('@')
        nickserver_uri = self._get_nicknym_uri(provider)

        cert_path = _get_ca_cert_path(self._basedir, provider)
        api_uri = self._get_api_uri(provider)

        if not token:
            token = self.service.tokens.get(userid)

        km_args = (userid, nickserver_uri, soledad)

        km_kwargs = {
            "token": token, "uid": uuid,
            "api_uri": api_uri, "api_version": "1",
            "ca_cert_path": cert_path,
            "gpgbinary": get_gpg_bin_path()
        }
        keymanager = KeyManager(*km_args, **km_kwargs)
        return keymanager

    def _get_api_uri(self, provider):
        # TODO get this from service.json (use bonafide service)
        api_uri = "https://api.{provider}:4430".format(
            provider=provider)
        return api_uri

    def _get_nicknym_uri(self, provider):
        return 'https://nicknym.{provider}:6425'.format(
            provider=provider)


class KeymanagerService(HookableService):

    def __init__(self, basedir=DEFAULT_BASEDIR):
        service.Service.__init__(self)
        self._basedir = basedir
        self._container = None

    def startService(self):
        logger.debug('starting Keymanager Service')
        self._container = KeymanagerContainer(self._basedir)
        self._container.service = self
        self.tokens = {}
        super(KeymanagerService, self).startService()

    # hooks

    def hook_on_new_soledad_instance(self, **kw):
        container = self._container
        user = kw['user']
        token = kw['token']
        uuid = kw['uuid']
        soledad = kw['soledad']
        if not container.get_instance(user):
            logger.debug('Adding a new Keymanager instance for %s' % user)
            if not token:
                token = self.tokens.get(user)
            container.add_instance(user, token, uuid, soledad)

    def hook_on_bonafide_auth(self, **kw):
        userid = kw['username']
        provider = _get_provider_from_full_userid(userid)
        provider.callWhenReady(self._hook_on_bonafide_auth, provider, **kw)

    def _hook_on_bonafide_auth(self, provider, **kw):
        if provider.offers_service('mx'):
            userid = kw['username']
            token = kw['token']

            container = self._container
            if container.get_instance(userid):
                logger.debug(
                    'passing a new SRP Token '
                    'to Keymanager: %s' % userid)
                container.set_remote_auth_token(userid, token)
            else:
                logger.debug('storing the keymanager token... %s ' % token)
                self.tokens[userid] = token

    # commands

    def do_list_keys(self, userid, private=False):
        km = self._container.get_instance(userid['user'])
        d = km.get_all_keys(private=private)
        d.addCallback(lambda keys: [dict(key) for key in keys])
        return d

    def do_export(self, userid, address, private=False):
        km = self._container.get_instance(userid['user'])
        d = km.get_key(address, private=private, fetch_remote=False)
        d.addCallback(lambda key: dict(key))
        return d

    def do_insert(self, userid, address, rawkey, validation='Fingerprint'):
        km = self._container.get_instance(userid['user'])
        validation = ValidationLevels.get(validation)
        d = km.put_raw_key(rawkey, address, validation=validation)
        d.addCallback(lambda _: km.get_key(address, fetch_remote=False))
        d.addCallback(lambda key: dict(key))
        return d

    @defer.inlineCallbacks
    def do_delete(self, userid, address, private=False):
        km = self._container.get_instance(userid['user'])
        key = yield km.get_key(address, private=private, fetch_remote=False)
        km.delete_key(key)
        defer.returnValue(key.fingerprint)


class StandardMailService(service.MultiService, HookableService):
    """
    A collection of Services.

    This is the parent service, that launches 3 different services that expose
    Encrypted Mail Capabilities on specific ports:

        - SMTP service, on port 2013
        - IMAP service, on port 1984
        - The IncomingMail Service, which doesn't listen on any port, but
          watches and processes the Incoming Queue and saves the processed mail
          into the matching INBOX.
    """

    name = 'mail'

    # TODO factor out Mail Service to inside mail package.

    def __init__(self, basedir):
        self._basedir = basedir
        self._soledad_sessions = {}
        self._keymanager_sessions = {}
        self._sendmail_opts = {}
        self._service_tokens = {}
        self._active_user = None
        super(StandardMailService, self).__init__()
        self.initializeChildrenServices()

    def initializeChildrenServices(self):
        self.addService(IMAPService(self._soledad_sessions))
        self.addService(SMTPService(
            self._soledad_sessions, self._keymanager_sessions,
            self._sendmail_opts))
        # TODO adapt the service to receive soledad/keymanager sessions object.
        # See also the TODO before IncomingMailService.startInstance
        self.addService(IncomingMailService(self))

    def startService(self):
        logger.info('starting mail service')
        super(StandardMailService, self).startService()

    def stopService(self):
        logger.info('stopping mail service')
        super(StandardMailService, self).stopService()

    def startInstance(self, userid, soledad, keymanager):
        username, provider = userid.split('@')

        self._soledad_sessions[userid] = soledad
        self._keymanager_sessions[userid] = keymanager

        sendmail_opts = _get_sendmail_opts(self._basedir, provider, username)
        self._sendmail_opts[userid] = sendmail_opts

        incoming = self.getServiceNamed('incoming_mail')
        incoming.startInstance(userid)

        def registerToken(token):
            self._service_tokens[userid] = token
            self._active_user = userid
            return token

        d = soledad.get_or_create_service_token('mail_auth')
        d.addCallback(registerToken)
        d.addCallback(self._write_tokens_file, userid)
        return d

    # hooks

    def hook_on_new_keymanager_instance(self, **kw):
        # XXX we can specify this as a waterfall, or just AND the two
        # conditions.
        userid = kw['userid']
        soledad = kw['soledad']
        keymanager = kw['keymanager']

        # TODO --- only start instance if "autostart" is True.
        self.startInstance(userid, soledad, keymanager)

    @defer.inlineCallbacks
    def hook_on_bonafide_auth(self, **kw):
        # TODO: if it's expired we should renew it
        userid = kw['username']

        self._maybe_start_incoming_service(userid)
        yield self._maybe_fetch_smtp_certificate(userid)

    def _maybe_start_incoming_service(self, userid):
        """
        try to turn on incoming mail service for the user that just logged in
        """
        logger.debug(
            'looking for incoming mail service for auth: %s' % userid)
        multiservice = self.getServiceNamed('incoming_mail')
        try:
            incoming = multiservice.getServiceNamed(userid)
            incoming.startService()
        except KeyError:
            logger.debug('no incoming service for %s' % userid)

    @defer.inlineCallbacks
    def _maybe_fetch_smtp_certificate(self, userid):
        # check if smtp cert exists
        username, provider = userid.split('@')
        cert_path = _get_smtp_client_cert_path(self._basedir, provider,
                                               username)
        if os.path.exists(cert_path):
            defer.returnValue(None)

        # fetch smtp cert and store
        bonafide = self.parent.getServiceNamed("bonafide")
        _, cert_str = yield bonafide.do_get_smtp_cert(userid)

        cert_dir = os.path.dirname(cert_path)
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir, mode=0700)
        with open(cert_path, 'w') as outf:
            outf.write(cert_str)
        check_and_fix_urw_only(cert_path)

    def hook_on_bonafide_logout(self, **kw):
        username = kw.get('username', None)
        if username:
            multiservice = self.getServiceNamed('incoming_mail')
            try:
                incoming = multiservice.getServiceNamed(username)
            except KeyError:
                incoming = None
            if incoming:
                logger.debug(
                    'looking for incoming mail service '
                    'for logout: %s' % username)
                incoming.stopService()

    # commands

    def do_status(self):
        status = 'running' if self.running else 'disabled'
        return {'mail': status}

    def get_token(self):
        active_user = self._active_user
        if not active_user:
            return defer.succeed({'user': None})
        token = self._service_tokens.get(active_user)
        return defer.succeed({'user': active_user, 'token': token})

    # access to containers

    def get_soledad_session(self, userid):
        return self._soledad_sessions.get(userid)

    def get_keymanager_session(self, userid):
        return self._keymanager_sessions.get(userid)

    def _write_tokens_file(self, token, userid):
        tokens_folder = os.path.join(tempfile.gettempdir(), "bitmask_tokens")
        if os.path.exists(tokens_folder):
            try:
                shutil.rmtree(tokens_folder)
            except OSError as e:
                logger.warn("Can't remove tokens folder %s: %s"
                            % (tokens_folder, e))
                return
        os.mkdir(tokens_folder, 0700)

        tokens_path = os.path.join(tokens_folder,
                                   "%s.json" % (userid,))
        token_dict = {'mail_auth': self._service_tokens[userid]}
        with open(tokens_path, 'w') as ftokens:
            json.dump(token_dict, ftokens)


class IMAPService(service.Service):

    name = 'imap'

    def __init__(self, soledad_sessions):
        self._soledad_sessions = soledad_sessions
        self._port = None
        self._factory = None
        super(IMAPService, self).__init__()

    def startService(self):
        logger.info('starting imap service')
        port, factory = imap_service.run_service(
            self._soledad_sessions, factory=self._factory)
        self._port = port
        self._factory = factory
        super(IMAPService, self).startService()

    def stopService(self):
        logger.info("stopping imap service")
        if self._port:
            self._port.stopListening()
            self._port = None
        if self._factory:
            self._factory.doStop()
        super(IMAPService, self).stopService()


class SMTPService(service.Service):

    name = 'smtp'

    def __init__(self, soledad_sessions, keymanager_sessions, sendmail_opts,
                 basedir=DEFAULT_BASEDIR):

        self._basedir = os.path.expanduser(basedir)
        self._soledad_sessions = soledad_sessions
        self._keymanager_sessions = keymanager_sessions
        self._sendmail_opts = sendmail_opts
        self._port = None
        self._factory = None
        super(SMTPService, self).__init__()

    def startService(self):
        logger.info('starting smtp service')
        port, factory = smtp_service.run_service(
            self._soledad_sessions,
            self._keymanager_sessions,
            self._sendmail_opts,
            factory=self._factory)
        self._port = port
        self._factory = factory
        super(SMTPService, self).startService()

    def stopService(self):
        logger.info('stopping smtp service')
        if self._port:
            self._port.stopListening()
            self._port = None
        if self._factory:
            self._factory.doStop()
        super(SMTPService, self).stopService()


class IncomingMailService(service.MultiService):
    """
    Manage child services that check for incoming mail for individual users.
    """

    name = 'incoming_mail'

    def __init__(self, mail_service):
        super(IncomingMailService, self).__init__()
        self._mail = mail_service

    def startService(self):
        logger.info('starting incoming mail service')
        super(IncomingMailService, self).startService()

    def stopService(self):
        super(IncomingMailService, self).stopService()

    # Individual accounts

    def startInstance(self, userid):
        soledad = self._mail.get_soledad_session(userid)
        keymanager = self._mail.get_keymanager_session(userid)

        logger.info('setting up incoming mail service for %s' % userid)
        self._start_incoming_mail_instance(
            keymanager, soledad, userid)

    def _start_incoming_mail_instance(self, keymanager, soledad,
                                      userid, start_sync=True):

        def setUpIncomingMail(inbox):
            incoming_mail = IncomingMail(
                keymanager, soledad,
                inbox, userid,
                check_period=INCOMING_CHECK_PERIOD)
            logger.debug('setting incoming mail service for %s' % userid)
            incoming_mail.setName(userid)
            self.addService(incoming_mail)

        acc = Account(soledad, userid)
        d = acc.callWhenReady(
            lambda _: acc.get_collection_by_mailbox(INBOX_NAME))
        d.addCallback(setUpIncomingMail)
        d.addErrback(lambda r: logger.error(str(r)))
        return d

# --------------------------------------------------------------------
#
# config utilities. should be moved to bonafide
#


SERVICES = ('soledad', 'smtp', 'eip')


Provider = namedtuple(
    'Provider', ['hostname', 'ip_address', 'location', 'port'])

SendmailOpts = namedtuple(
    'SendmailOpts', ['cert', 'key', 'hostname', 'port'])


def _get_ca_cert_path(basedir, provider):
    path = os.path.join(
        basedir, 'providers', provider, 'keys', 'ca', 'cacert.pem')
    return path


def _get_sendmail_opts(basedir, provider, username):
    cert = _get_smtp_client_cert_path(basedir, provider, username)
    key = cert
    prov = _get_provider_for_service('smtp', basedir, provider)
    hostname = prov.hostname
    port = prov.port
    opts = SendmailOpts(cert, key, hostname, port)
    return opts


def _get_smtp_client_cert_path(basedir, provider, username):
    path = os.path.join(
        basedir, 'providers', provider, 'keys', 'client', 'smtp_%s.pem' %
        username)
    return path


def _get_config_for_service(service, basedir, provider):
    if service not in SERVICES:
        raise ImproperlyConfigured('Tried to use an unknown service')

    config_path = os.path.join(
        basedir, 'providers', provider, '%s-service.json' % service)
    try:
        with open(config_path) as config:
            config = json.loads(config.read())
    except IOError:
        # FIXME might be that the provider DOES NOT offer this service!
        raise ImproperlyConfigured(
            'could not open config file %s' % config_path)
    else:
        return config


def first(xs):
    return xs[0]


def _pick_server(config, strategy=first):
    """
    Picks a server from a list of possible choices.
    The service files have a  <describe>.
    This implementation just picks the FIRST available server.
    """
    servers = config['hosts'].keys()
    choice = config['hosts'][strategy(servers)]
    return choice


def _get_subdict(d, keys):
    return {key: d.get(key) for key in keys}


def _get_provider_for_service(service, basedir, provider):

    if service not in SERVICES:
        raise ImproperlyConfigured('Tried to use an unknown service')

    config = _get_config_for_service(service, basedir, provider)
    p = _pick_server(config)
    attrs = _get_subdict(p, ('hostname', 'ip_address', 'location', 'port'))
    provider = Provider(**attrs)
    return provider


def _get_smtp_uri(basedir, provider):
    prov = _get_provider_for_service('smtp', basedir, provider)
    url = 'https://{hostname}:{port}'.format(
        hostname=prov.hostname, port=prov.port)
    return url


def _get_soledad_uri(basedir, provider):
    prov = _get_provider_for_service('soledad', basedir, provider)
    url = 'https://{hostname}:{port}'.format(
        hostname=prov.hostname, port=prov.port)
    return url
