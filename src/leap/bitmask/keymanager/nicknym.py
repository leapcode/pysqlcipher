# -*- coding: utf-8 -*-
# nicknym.py
# Copyright (C) 2016 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import json
import sys
import logging
import urllib

from twisted.internet import defer
from twisted.web import client
from twisted.web._responses import NOT_FOUND

from leap.bitmask.keymanager.errors import KeyNotFound
from leap.common.check import leap_assert
from leap.common.http import HTTPClient
from leap.common.decorators import memoized_method


logger = logging.getLogger(__name__)


class Nicknym(object):
    """
    Responsible for communication to the nicknym server.
    """

    PUBKEY_KEY = "user[public_key]"

    def __init__(self, nickserver_uri, ca_cert_path, token):
        self._nickserver_uri = nickserver_uri
        self._async_client_pinned = HTTPClient(ca_cert_path)
        self.token = token

    @defer.inlineCallbacks
    def put_key(self, uid, key_data, api_uri, api_version):
        """
        Send a PUT request to C{uri} containing C{data}.

        The request will be sent using the configured CA certificate path to
        verify the server certificate and the configured session id for
        authentication.

        :param uid: The URI of the request.
        :type uid: str
        :param key_data: The body of the request.
        :type key_data: dict, str or file

        :return: A deferred that will be fired when PUT request finishes
        :rtype: Deferred
        """
        data = {
            self.PUBKEY_KEY: key_data
        }

        uri = "%s/%s/users/%s.json" % (
            api_uri,
            api_version,
            uid)

        leap_assert(
            self.token is not None,
            'We need a token to interact with webapp!')
        if type(data) == dict:
            data = urllib.urlencode(data)
        headers = {'Authorization': [str('Token token=%s' % self.token)]}
        headers['Content-Type'] = ['application/x-www-form-urlencoded']
        try:
            res = yield self._async_client_pinned.request(str(uri), 'PUT',
                                                          body=str(data),
                                                          headers=headers)
        except Exception as e:
            logger.warning("Error uploading key: %r" % (e,))
            raise e
        if 'error' in res:
            # FIXME: That's a workaround for 500,
            # we need to implement a readBody to assert response code
            logger.warning("Error uploading key: %r" % (res,))
            raise Exception(res)

    @defer.inlineCallbacks
    def _get_key_from_nicknym(self, uri):
        """
        Send a GET request to C{uri} containing C{data}.

        :param uri: The URI of the request.
        :type uri: str

        :return: A deferred that will be fired with GET content as json (dict)
        :rtype: Deferred
        """
        try:
            content = yield self._fetch_and_handle_404_from_nicknym(uri)
            json_content = json.loads(content)

        except KeyNotFound:
            raise
        except IOError as e:
            logger.warning("HTTP error retrieving key: %r" % (e,))
            logger.warning("%s" % (content,))
            raise KeyNotFound(e.message), None, sys.exc_info()[2]
        except ValueError as v:
            logger.warning("Invalid JSON data from key: %s" % (uri,))
            raise KeyNotFound(v.message + ' - ' + uri), None, sys.exc_info()[2]

        except Exception as e:
            logger.warning("Error retrieving key: %r" % (e,))
            raise KeyNotFound(e.message), None, sys.exc_info()[2]
        # Responses are now text/plain, although it's json anyway, but
        # this will fail when it shouldn't
        # leap_assert(
        #     res.headers['content-type'].startswith('application/json'),
        #     'Content-type is not JSON.')
        defer.returnValue(json_content)

    def _fetch_and_handle_404_from_nicknym(self, uri):
        """
        Send a GET request to C{uri} containing C{data}.

        :param uri: The URI of the request.
        :type uri: str

        :return: A deferred that will be fired with GET content as json (dict)
        :rtype: Deferred
        """

        def check_404(response):
            if response.code == NOT_FOUND:
                message = ' %s: Key not found. Request: %s' \
                          % (response.code, uri)
                logger.warning(message)
                raise KeyNotFound(message), None, sys.exc_info()[2]
            return response

        d = self._async_client_pinned.request(str(uri), 'GET',
                                              callback=check_404)
        d.addCallback(client.readBody)
        return d

    @memoized_method(invalidation=300)
    def fetch_key_with_address(self, address):
        """
        Fetch keys bound to address from nickserver.

        :param address: The address bound to the keys.
        :type address: str

        :return: A Deferred which fires when the key is in the storage,
                 or which fails with KeyNotFound if the key was not found on
                 nickserver.
        :rtype: Deferred

        """
        return self._get_key_from_nicknym(self._nickserver_uri +
                                          '?address=' + address)

    @memoized_method(invalidation=300)
    def fetch_key_with_fingerprint(self, fingerprint):
        """
        Fetch keys bound to fingerprint from nickserver.

        :param fingerprint: The fingerprint bound to the keys.
        :type fingerprint: str

        :return: A Deferred which fires when the key is in the storage,
                 or which fails with KeyNotFound if the key was not found on
                 nickserver.
        :rtype: Deferred

        """
        return self._get_key_from_nicknym(self._nickserver_uri +
                                          '?fingerprint=' + fingerprint)
