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
import os
import sys

from leap.bonafide._http import httpRequest

from leap.common.check import leap_assert
from leap.common.config import get_path_prefix as common_get_path_prefix
from leap.common.files import check_and_fix_urw_only, get_mtime, mkdir_p


APPNAME = "bonafide"
ENDPOINT = "ipc:///tmp/%s.sock" % APPNAME


def get_path_prefix(standalone=False):
    return common_get_path_prefix(standalone)


def get_provider_path(domain):
    """
    Returns relative path for provider config.

    :param domain: the domain to which this providerconfig belongs to.
    :type domain: str
    :returns: the path
    :rtype: str
    """
    leap_assert(domain is not None, "get_provider_path: We need a domain")
    return os.path.join("leap", "providers", domain, "provider.json")


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
    return "%s@%s" % (user, provider)


def get_username_and_provider(full_id):
    return full_id.split('@')


class ProviderConfig(object):
    # TODO add file config for enabled services

    def __init__(self, domain):
        self._api_base = None
        self._domain = domain

    def is_configured(self):
        provider_json = self._get_provider_json_path()
        # XXX check if all the services are there
        if is_file(provider_json):
            return True
        return False

    def download_provider_info(self):
        """
        Download the provider.json info from the main domain.
        This SHOULD only be used once with the DOMAIN url.
        """
        # TODO handle pre-seeded providers?
        # or let client handle that? We could move them to bonafide.
        provider_json = self._get_provider_json_path()
        if is_file(provider_json):
            raise RuntimeError('File already exists')

    def update_provider_info(self):
        """
        Get more recent copy of provider.json from the api URL.
        """
        pass

    def _http_request(self, *args, **kw):
        # XXX pass if-modified-since header
        return httpRequest(*args, **kw)

    def _get_provider_json_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        provider_json = os.path.join(get_path_prefix(), get_provider_path(domain))
        return provider_json

if __name__ == '__main__':
    config = ProviderConfig('cdev.bitmask.net')
    config.is_configured()
    config.download_provider_info()
