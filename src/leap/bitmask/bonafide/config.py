# -*- coding: utf-8 -*-
# config.py
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
Configuration for a LEAP provider.
"""
import datetime
import json
import os
import platform
import shutil
import sys

from collections import defaultdict
from urlparse import urlparse

from twisted.internet import defer, reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.logger import Logger
from twisted.web.client import Agent, downloadPage

from leap.bitmask.bonafide._http import httpRequest
from leap.bitmask.bonafide.provider import Discovery
from leap.bitmask.bonafide.errors import NotConfiguredError, NetworkError

from leap.common.check import leap_assert
from leap.common.config import get_path_prefix as common_get_path_prefix
from leap.common.files import mkdir_p

logger = Logger()


APPNAME = "bonafide"
if platform.system() == 'Windows':
    ENDPOINT = "tcp://127.0.0.1:5001"
else:
    ENDPOINT = "ipc:///tmp/%s.sock" % APPNAME


def get_path_prefix(standalone=False):
    return common_get_path_prefix(standalone)


_preffix = get_path_prefix()


def get_provider_path(domain, config='provider.json'):
    """
    Returns relative path for provider configs.

    :param domain: the domain to which this providerconfig belongs to.
    :type domain: str
    :returns: the path
    :rtype: str
    """
    # TODO sanitize domain
    leap_assert(domain is not None, 'get_provider_path: We need a domain')
    return os.path.join('providers', domain, config)


def get_ca_cert_path(domain):
    # TODO sanitize domain
    leap_assert(domain is not None, 'get_provider_path: We need a domain')
    return os.path.join('providers', domain, 'keys', 'ca', 'cacert.pem')


def get_modification_ts(path):
    """
    Gets modification time of a file.

    :param path: the path to get ts from
    :type path: str
    :returns: modification time
    :rtype: datetime object
    """
    ts = os.path.getmtime(path)
    return datetime.datetime.fromtimestamp(ts)


def update_modification_ts(path):
    """
    Sets modification time of a file to current time.

    :param path: the path to set ts to.
    :type path: str
    :returns: modification time
    :rtype: datetime object
    """
    os.utime(path, None)
    return get_modification_ts(path)


def is_file(path):
    """
    Returns True if the path exists and is a file.
    """
    return os.path.isfile(path)


def is_empty_file(path):
    """
    Returns True if the file at path is empty.
    """
    return os.stat(path).st_size is 0


def make_address(user, provider):
    """
    Return a full identifier for an user, as a email-like
    identifier.

    :param user: the username
    :type user: basestring
    :param provider: the provider domain
    :type provider: basestring
    """
    return '%s@%s' % (user, provider)


def get_username_and_provider(full_id):
    return full_id.split('@')


def list_providers():
    path = os.path.join(_preffix, "leap", "providers")
    path = os.path.expanduser(path)
    if not os.path.isdir(path):
        os.makedirs(path)
    return os.listdir(path)


def delete_provider(domain):
    path = os.path.join(_preffix, "leap", "providers", domain)
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        raise NotConfiguredError("Provider %s is not configured, can't be "
                                 "deleted" % (domain,))
    shutil.rmtree(path)

    # FIXME: this feels hacky, can we find a better way??
    if domain in Provider.first_bootstrap:
        del Provider.first_bootstrap[domain]
    if domain in Provider.ongoing_bootstrap:
        del Provider.ongoing_bootstrap[domain]


class Provider(object):
    # TODO add validation

    SERVICES_MAP = {
        'openvpn': ['eip'],
        'mx': ['soledad', 'smtp']}

    first_bootstrap = defaultdict(None)
    ongoing_bootstrap = defaultdict(None)
    stuck_bootstrap = defaultdict(None)

    def __init__(self, domain, autoconf=False, basedir=None,
                 check_certificate=True):
        # TODO: I need a way to know if it was already configured
        if not basedir:
            basedir = os.path.join(_preffix, 'leap')
        self._basedir = os.path.expanduser(basedir)
        self._domain = domain
        self._disco = Discovery('https://%s' % domain)
        self._provider_config = None

        is_configured = self.is_configured()
        if not is_configured:
            check_certificate = False

        if check_certificate:
            self.contextFactory = None
        else:
            # XXX we should do this only for the FIRST provider download.
            # For the rest, we should pass the ca cert to the agent.
            # That means that RIGHT AFTER DOWNLOADING provider_info,
            # we should instantiate a new Agent...
            self.contextFactory = WebClientContextFactory()
        self._agent = Agent(reactor, self.contextFactory)

        self._load_provider_json()

        if not is_configured:
            if autoconf:
                logger.debug(
                    'provider %s not configured: downloading files...' %
                    domain)
                self.bootstrap()
            else:
                raise NotConfiguredError("Provider %s is not configured"
                                         % (domain,))
        else:
            logger.debug('provider already initialized')
            self.first_bootstrap[self._domain] = defer.succeed(
                'already_initialized')
            self.ongoing_bootstrap[self._domain] = defer.succeed(
                'already_initialized')

    @property
    def domain(self):
        return self._domain

    @property
    def api_uri(self):
        if not self._provider_config:
            return 'https://api.%s:4430' % self._domain
        return self._provider_config.api_uri

    @property
    def version(self):
        if not self._provider_config:
            return 1
        return int(self._provider_config.api_version)

    def is_configured(self):
        provider_json = self._get_provider_json_path()
        if not is_file(provider_json):
            return False
        if not is_file(self._get_ca_cert_path()):
            return False
        return True

    def config(self):
        if not self._provider_config:
            self._load_provider_json()
        return self._provider_config.dict()

    def bootstrap(self):
        domain = self._domain
        logger.debug("bootstrapping provider %s" % domain)
        ongoing = self.ongoing_bootstrap.get(domain)
        if ongoing:
            logger.debug('already bootstrapping this provider...')
            return

        self.first_bootstrap[self._domain] = defer.Deferred()

        def first_bootstrap_done(ignored):
            try:
                self.first_bootstrap[domain].callback('got config')
            except defer.AlreadyCalledError:
                pass

        d = self.maybe_download_provider_info()
        d.addCallback(self.maybe_download_ca_cert)
        d.addCallback(self.validate_ca_cert)
        d.addCallback(first_bootstrap_done)
        d.addCallback(self.maybe_download_services_config)
        self.ongoing_bootstrap[domain] = d

    def callWhenMainConfigReady(self, cb, *args, **kw):
        d = self.first_bootstrap[self._domain]
        d.addCallback(lambda _: cb(*args, **kw))
        return d

    def callWhenReady(self, cb, *args, **kw):
        d = self.ongoing_bootstrap[self._domain]
        d.addCallback(lambda _: cb(*args, **kw))
        return d

    def has_valid_certificate(self):
        pass

    def maybe_download_provider_info(self, replace=False):
        """
        Download the provider.json info from the main domain.
        This SHOULD only be used once with the DOMAIN url.
        """
        # TODO handle pre-seeded providers?
        # or let client handle that? We could move them to bonafide.
        provider_json = self._get_provider_json_path()
        if is_file(provider_json) and not replace:
            return defer.succeed('provider_info_already_exists')

        folders, f = os.path.split(provider_json)
        mkdir_p(folders)

        uri = self._disco.get_provider_info_uri()
        met = self._disco.get_provider_info_method()

        def errback(failure):
            shutil.rmtree(folders)
            raise NetworkError(failure.getErrorMessage())

        d = downloadPage(uri, provider_json, method=met)
        d.addCallback(lambda _: self._load_provider_json())
        d.addErrback(errback)
        return d

    def update_provider_info(self):
        """
        Get more recent copy of provider.json from the api URL.
        """
        pass

    def maybe_download_ca_cert(self, ignored):
        """
        :rtype: deferred
        """

        def errback(self, failure):
            raise NetworkError(failure.getErrorMessage())

        path = self._get_ca_cert_path()
        if is_file(path):
            return defer.succeed('ca_cert_path_already_exists')

        uri = self._get_ca_cert_uri()
        mkdir_p(os.path.split(path)[0])
        d = downloadPage(uri, path)
        d.addErrback(errback)
        return d

    def validate_ca_cert(self, ignored):
        # TODO Need to verify fingerprint against the one in provider.json
        expected = self._get_expected_ca_cert_fingerprint()
        print "EXPECTED FINGERPRINT:", expected

    def _get_expected_ca_cert_fingerprint(self):
        try:
            fgp = self._provider_config.ca_cert_fingerprint
        except AttributeError:
            fgp = None
        return fgp

    # Services config files

    def has_fetched_services_config(self):
        return os.path.isfile(self._get_configs_path())

    def maybe_download_services_config(self, ignored):

        # TODO --- currently, some providers (mail.bitmask.net) raise 401
        # UNAUTHENTICATED if we try to get the services
        # See: # https://leap.se/code/issues/7906

        def further_bootstrap_needs_auth(ignored):
            logger.warn('cannot download services config yet, need auth')
            pending_deferred = defer.Deferred()
            self.stuck_bootstrap[self._domain] = pending_deferred
            return defer.succeed('ok for now')

        uri, met, path = self._get_configs_download_params()

        d = downloadPage(uri, path, method=met)
        d.addCallback(lambda _: self._load_provider_json())
        d.addCallback(
            lambda _: self._get_config_for_all_services(session=None))
        d.addErrback(further_bootstrap_needs_auth)
        return d

    def download_services_config_with_auth(self, session):

        def verify_provider_configs(ignored):
            self._load_provider_configs()
            return True

        def workaround_for_config_fetch(failure):
            # FIXME --- configs.json raises 500, see #7914.
            # This is a workaround until that's fixed.
            logger.error(failure)
            logger.debug(
                "COULD NOT VERIFY CONFIGS.JSON, WORKAROUND: DIRECT DOWNLOAD")

            if 'mx' in self._provider_config.services:
                soledad_uri = '/1/config/soledad-service.json'
                smtp_uri = '/1/config/smtp-service.json'
                base = self._disco.netloc

                fetch = self._fetch_provider_configs_unauthenticated
                get_path = self._get_service_config_path

                d1 = fetch(
                    'https://' + str(base + soledad_uri), get_path('soledad'))
                d2 = fetch(
                    'https://' + str(base + smtp_uri), get_path('smtp'))
                d = defer.gatherResults([d1, d2])
                d.addCallback(lambda _: finish_stuck_after_workaround())
                return d

        def finish_stuck_after_workaround():
            stuck = self.stuck_bootstrap.get(self._domain, None)
            if stuck:
                stuck.callback('continue!')

        def complete_bootstrapping(ignored):
            stuck = self.stuck_bootstrap.get(self._domain, None)
            if stuck:
                d = self._get_config_for_all_services(session)
                d.addCallback(lambda _: stuck.callback('continue!'))
                d.addErrback(logger.error)
                return d

        if not self.has_fetched_services_config():
            self._load_provider_json()
            uri, met, path = self._get_configs_download_params()
            d = session.fetch_provider_configs(uri, path)
            d.addCallback(verify_provider_configs)
            d.addCallback(complete_bootstrapping)
            d.addErrback(workaround_for_config_fetch)
            return d
        else:
            d = defer.succeed('already downloaded')
            d.addCallback(complete_bootstrapping)
            return d

    def _get_configs_download_params(self):
        uri = self._disco.get_configs_uri()
        met = self._disco.get_configs_method()
        path = self._get_configs_path()
        return uri, met, path

    def offers_service(self, service):
        if service not in self.SERVICES_MAP.keys():
            raise RuntimeError('Unknown service: %s' % service)
        return service in self._provider_config.services

    def is_service_enabled(self, service):
        # TODO implement on some config file
        return True

    def has_config_for_service(self, service):
        has_file = os.path.isfile
        path = self._get_service_config_path
        smap = self.SERVICES_MAP

        result = all([has_file(path(subservice)) for
                      subservice in smap[service]])
        return result

    def has_config_for_all_services(self):
        self._load_provider_json()
        if not self._provider_config:
            return False
        all_services = self._provider_config.services
        has_all = all(
            [self.has_config_for_service(service) for service in
             all_services])
        return has_all

    def _get_provider_json_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        provider_json_path = os.path.join(
            self._basedir, get_provider_path(domain, config='provider.json'))
        return provider_json_path

    def _get_configs_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        configs_path = os.path.join(
            self._basedir, get_provider_path(domain, config='configs.json'))
        return configs_path

    def _get_service_config_path(self, service):
        domain = self._domain.encode(sys.getfilesystemencoding())
        configs_path = os.path.join(
            self._basedir, get_provider_path(
                domain, config='%s-service.json' % service))
        return configs_path

    def _get_ca_cert_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        cert_path = os.path.join(self._basedir, get_ca_cert_path(domain))
        return cert_path

    def _get_ca_cert_uri(self):
        try:
            uri = self._provider_config.ca_cert_uri
            uri = str(uri)
        except Exception:
            uri = None
        return uri

    def _load_provider_json(self):
        path = self._get_provider_json_path()
        if not is_file(path):
            logger.debug("cannot LOAD provider config path %s" % path)
            return

        with open(path, 'r') as config:
            self._provider_config = Record(**json.load(config))

        api_uri = self._provider_config.api_uri
        if api_uri:
            parsed = urlparse(api_uri)
            self._disco.netloc = parsed.netloc

    def _get_config_for_all_services(self, session):
        services_dict = self._load_provider_configs()
        configs_path = self._get_configs_path()
        with open(configs_path) as jsonf:
            services_dict = Record(**json.load(jsonf)).services
        pending = []
        base = self._disco.get_base_uri()
        for service in self._provider_config.services:
            if service in self.SERVICES_MAP.keys():
                for subservice in self.SERVICES_MAP[service]:
                    uri = base + str(services_dict[subservice])
                    path = self._get_service_config_path(subservice)
                    if session:
                        d = session.fetch_provider_configs(uri, path)
                    else:
                        d = self._fetch_provider_configs_unauthenticated(
                            uri, path)
                    pending.append(d)
        return defer.gatherResults(pending)

    def _load_provider_configs(self):
        configs_path = self._get_configs_path()
        with open(configs_path) as jsonf:
            services_dict = Record(**json.load(jsonf)).services
        return services_dict

    def _fetch_provider_configs_unauthenticated(self, uri, path):
        logger.info('downloading config for %s...' % uri)
        d = downloadPage(uri, path, method='GET')
        return d

    def _http_request(self, *args, **kw):
        # XXX pass if-modified-since header
        return httpRequest(self._agent, *args, **kw)


class Record(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def dict(self):
        return self.__dict__


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)


if __name__ == '__main__':

    def print_done():
        print '>>> bootstrapping done!!!'

    provider = Provider('cdev.bitmask.net')
    provider.callWhenReady(print_done)
    reactor.run()
