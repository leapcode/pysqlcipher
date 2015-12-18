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
import sys

from twisted.internet import defer, reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.python import log
from twisted.web.client import Agent, downloadPage

from leap.bonafide._http import httpRequest
from leap.bonafide.provider import Discovery

from leap.common.check import leap_assert
from leap.common.config import get_path_prefix as common_get_path_prefix
from leap.common.files import mkdir_p
# check_and_fix_urw_only, get_mtime


APPNAME = "bonafide"
ENDPOINT = "ipc:///tmp/%s.sock" % APPNAME


def get_path_prefix(standalone=False):
    return common_get_path_prefix(standalone)


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


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)


class Provider(object):
    # TODO split Provider, ProviderConfig
    # TODO add validation

    SERVICES_MAP = {
        'openvpn': ['eip'],
        'mx': ['soledad', 'smtp']}

    def __init__(self, domain, autoconf=True, basedir='~/.config/leap',
                 check_certificate=True):
        self._domain = domain
        self._basedir = os.path.expanduser(basedir)
        self._disco = Discovery('https://%s' % domain)
        self._provider_config = {}

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

        self._load_provider_config()
        # TODO if loaded, setup _get_api_uri on the DISCOVERY

        self._init_deferred = None

        if not is_configured and autoconf:
            print 'provider %s not configured: downloading files...' % domain
            self.bootstrap()
        else:
            print 'already initialized'
            self._init_deferred = defer.succeed('already_initialized')

    def callWhenReady(self, cb, *args, **kw):
        print 'calling when ready', cb
        d = self._init_deferred
        d.addCallback(lambda _: cb(*args, **kw))
        d.addErrback(log.err)
        return d

    def is_configured(self):
        provider_json = self._get_provider_json_path()
        # XXX check if all the services are there
        if not is_file(provider_json):
            return False
        if not is_file(self._get_ca_cert_path()):
            return False
        return True

    def bootstrap(self):
        print "Bootstrapping provider %s" % self._domain
        d = self.maybe_download_provider_info()
        d.addCallback(self.maybe_download_ca_cert)
        d.addCallback(self.validate_ca_cert)
        d.addCallback(self.maybe_download_services_config)
        d.addCallback(self.load_services_config)
        self._init_deferred = d

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

        d = downloadPage(uri, provider_json, method=met)
        d.addCallback(lambda _: self._load_provider_config())
        d.addErrback(log.err)
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
        path = self._get_ca_cert_path()
        if is_file(path):
            return defer.succeed('ca_cert_path_already_exists')

        uri = self._get_ca_cert_uri()
        mkdir_p(os.path.split(path)[0])
        d = downloadPage(uri, path)
        d.addErrback(log.err)
        return d

    def validate_ca_cert(self, ignored):
        # XXX Need to verify fingerprint against the one in provider.json
        expected = self._get_expected_ca_cert_fingerprint()
        print "EXPECTED FINGERPRINT:", expected

    def _get_expected_ca_cert_fingerprint(self):
        try:
            fgp = self._provider_config.ca_cert_fingerprint
        except AttributeError:
            fgp = None
        return fgp


    def maybe_download_services_config(self, ignored):
        pass

    def load_services_config(self, ignored):
        print 'loading services config...'
        configs_path = self._get_configs_path()

        uri = self._disco.get_configs_uri()
        met = self._disco.get_configs_method()

        # TODO --- currently, provider on mail.bitmask.net raises 401
        # UNAUTHENTICATED if we try to # get the services on first boostrap.
        # See: # https://leap.se/code/issues/7906

        # As a Workaround, these urls work though:
        # curl -k https://api.mail.bitmask.net:4430/1/config/smtp-service.json 
        # curl -k https://api.mail.bitmask.net:4430/1/config/soledad-service.json 

        print "GETTING SERVICES FROM...", uri

        d = downloadPage(uri, configs_path, method=met)
        d.addCallback(lambda _: self._load_provider_config())
        d.addCallback(lambda _: self._get_config_for_all_services())
        d.addErrback(log.err)
        return d

    def offers_service(self, service):
        if service not in self.SERVICES_MAP.keys():
            raise RuntimeError('Unknown service: %s' % service)
        return service in self._provider_config.services

    # TODO is_service_enabled ---> this belongs to core?

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

    def _load_provider_config(self):
        path = self._get_provider_json_path()
        if not is_file(path):
            return
        with open(path, 'r') as config:
            self._provider_config = Record(**json.load(config))

    def _get_config_for_all_services(self):
        configs_path = self._get_configs_path()
        with open(configs_path) as jsonf:
            services_dict = Record(**json.load(jsonf)).services
        pending = []
        base = self._disco.get_base_uri()
        for service in self._provider_config.services:
            for subservice in self.SERVICES_MAP[service]:
                uri = base + str(services_dict[subservice])
                path = self._get_service_config_path(subservice)
                d = self._fetch_config_for_service(uri, path)
                pending.append(d)
        return defer.gatherResults(pending)

    def _fetch_config_for_service(self, uri, path):
        log.msg('Downloading config for %s...' % uri)
        d = downloadPage(uri, path, method='GET')
        return d

    def _http_request(self, *args, **kw):
        # XXX pass if-modified-since header
        return httpRequest(self._agent, *args, **kw)

    def _get_api_uri(self):
        pass


class Record(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


if __name__ == '__main__':

    def print_done():
        print '>>> bootstrapping done!!!'

    provider = Provider('cdev.bitmask.net')
    provider.callWhenReady(print_done)
    reactor.run()
