# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2013 LEAP
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
"""
Key Manager is a Nicknym agent for LEAP client.
"""
# let's do a little sanity check to see if we're using the wrong gnupg
import fileinput
import os
import sys
import tempfile
import json
import urllib

from leap.common import ca_bundle

from ._version import get_versions

try:
    from gnupg.gnupg import GPGUtilities
    assert(GPGUtilities)  # pyflakes happy
    from gnupg import __version__ as _gnupg_version
    if '-' in _gnupg_version:
        # avoid Parsing it as LegacyVersion, get just
        # the release numbers:
        _gnupg_version = _gnupg_version.split('-')[0]
    from pkg_resources import parse_version
    # We need to make sure that we're not colliding with the infamous
    # python-gnupg
    assert(parse_version(_gnupg_version) >= parse_version('1.4.0'))

except (ImportError, AssertionError):
    print "*******"
    print "Ooops! It looks like there is a conflict in the installed version "
    print "of gnupg."
    print "GNUPG_VERSION:", _gnupg_version
    print
    print "Disclaimer: Ideally, we would need to work a patch and propose the "
    print "merge to upstream. But until then do: "
    print
    print "% pip uninstall python-gnupg"
    print "% pip install gnupg"
    print "*******"
    sys.exit(1)

import logging
import requests

from twisted.internet import defer
from urlparse import urlparse

from leap.common.check import leap_assert
from leap.common.http import HTTPClient
from leap.common.events import emit_async, catalog
from leap.common.decorators import memoized_method

from leap.keymanager.errors import (
    KeyNotFound,
    KeyAddressMismatch,
    KeyNotValidUpgrade,
    UnsupportedKeyTypeError,
    InvalidSignature
)
from leap.keymanager.validation import ValidationLevels, can_upgrade

from leap.keymanager.keys import (
    build_key_from_dict,
    KEYMANAGER_KEY_TAG,
    TAGS_PRIVATE_INDEX,
)
from leap.keymanager.openpgp import OpenPGPKey, OpenPGPScheme

__version__ = get_versions()['version']
del get_versions

logger = logging.getLogger(__name__)


#
# The Key Manager
#

class KeyManager(object):

    #
    # server's key storage constants
    #

    OPENPGP_KEY = 'openpgp'
    PUBKEY_KEY = "user[public_key]"

    def __init__(self, address, nickserver_uri, soledad, token=None,
                 ca_cert_path=None, api_uri=None, api_version=None, uid=None,
                 gpgbinary=None):
        """
        Initialize a Key Manager for user's C{address} with provider's
        nickserver reachable in C{nickserver_uri}.

        :param address: The email address of the user of this Key Manager.
        :type address: str
        :param nickserver_uri: The URI of the nickserver.
        :type nickserver_uri: str
        :param soledad: A Soledad instance for local storage of keys.
        :type soledad: leap.soledad.Soledad
        :param token: The token for interacting with the webapp API.
        :type token: str
        :param ca_cert_path: The path to the CA certificate.
        :type ca_cert_path: str
        :param api_uri: The URI of the webapp API.
        :type api_uri: str
        :param api_version: The version of the webapp API.
        :type api_version: str
        :param uid: The user's UID.
        :type uid: str
        :param gpgbinary: Name for GnuPG binary executable.
        :type gpgbinary: C{str}
        """
        self._address = address
        self._nickserver_uri = nickserver_uri
        self._soledad = soledad
        self._token = token
        self.ca_cert_path = ca_cert_path
        self.api_uri = api_uri
        self.api_version = api_version
        self.uid = uid
        # a dict to map key types to their handlers
        self._wrapper_map = {
            OpenPGPKey: OpenPGPScheme(soledad, gpgbinary=gpgbinary),
            # other types of key will be added to this mapper.
        }
        # the following are used to perform https requests
        self._fetcher = requests
        self._combined_ca_bundle = self._create_combined_bundle_file()
        self._async_client = HTTPClient(self._combined_ca_bundle)
        self._async_client_pinned = HTTPClient(self._ca_cert_path)

    #
    # destructor
    #

    def __del__(self):
        try:
            created_tmp_combined_ca_bundle = self._combined_ca_bundle not in \
                [ca_bundle.where(), self._ca_cert_path]
            if created_tmp_combined_ca_bundle:
                os.remove(self._combined_ca_bundle)
        except OSError:
            pass

    #
    # utilities
    #

    def _create_combined_bundle_file(self):
        leap_ca_bundle = ca_bundle.where()

        if self._ca_cert_path == leap_ca_bundle:
            return self._ca_cert_path   # don't merge file with itself
        elif not self._ca_cert_path:
            return leap_ca_bundle

        tmp_file = tempfile.NamedTemporaryFile(delete=False)

        with open(tmp_file.name, 'w') as fout:
            fin = fileinput.input(files=(leap_ca_bundle, self._ca_cert_path))
            for line in fin:
                fout.write(line)
            fin.close()

        return tmp_file.name

    def _key_class_from_type(self, ktype):
        """
        Given a class type, return a class

        :param ktype: string representation of a class name
        :type ktype: str

        :return: A class with the matching name
        :rtype: classobj or type
        """
        return filter(
            lambda klass: klass.__name__ == ktype,
            self._wrapper_map).pop()

    @defer.inlineCallbacks
    def _get_key_from_nicknym(self, address):
        """
        Send a GET request to C{uri} containing C{data}.

        :param address: The URI of the request.
        :type address: str

        :return: A deferred that will be fired with GET content as json (dict)
        :rtype: Deferred
        """
        try:
            uri = self._nickserver_uri + '?address=' + address
            content = yield self._async_client_pinned.request(str(uri), 'GET')
            json_content = json.loads(content)
        except IOError as e:
            # FIXME: 404 doesnt raise today, but it wont produce json anyway
            # if e.response.status_code == 404:
                # raise KeyNotFound(address)
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

    @defer.inlineCallbacks
    def _get_with_combined_ca_bundle(self, uri, data=None):
        """
        Send a GET request to C{uri} containing C{data}.

        Instead of using the ca_cert provided on construction time, this
        version also uses the default certificates shipped with leap.common

        :param uri: The URI of the request.
        :type uri: str
        :param data: The body of the request.
        :type data: dict, str or file

        :return: A deferred that will be fired with the GET response
        :rtype: Deferred
        """
        try:
            content = yield self._async_client.request(str(uri), 'GET')
        except Exception as e:
            logger.warning("There was a problem fetching key: %s" % (e,))
            raise KeyNotFound(uri)
        if not content:
            raise KeyNotFound(uri)
        defer.returnValue(content)

    @defer.inlineCallbacks
    def _put(self, uri, data=None):
        """
        Send a PUT request to C{uri} containing C{data}.

        The request will be sent using the configured CA certificate path to
        verify the server certificate and the configured session id for
        authentication.

        :param uri: The URI of the request.
        :type uri: str
        :param data: The body of the request.
        :type data: dict, str or file

        :return: A deferred that will be fired when PUT request finishes
        :rtype: Deferred
        """
        leap_assert(
            self._token is not None,
            'We need a token to interact with webapp!')
        if type(data) == dict:
            data = urllib.urlencode(data)
        headers = {'Authorization': [str('Token token=%s' % self._token)]}
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

    @memoized_method(invalidation=300)
    @defer.inlineCallbacks
    def _fetch_keys_from_server(self, address):
        """
        Fetch keys bound to address from nickserver and insert them in
        local database.

        :param address: The address bound to the keys.
        :type address: str

        :return: A Deferred which fires when the key is in the storage,
                 or which fails with KeyNotFound if the key was not found on
                 nickserver.
        :rtype: Deferred

        """
        # request keys from the nickserver
        server_keys = yield self._get_key_from_nicknym(address)

        # insert keys in local database
        if self.OPENPGP_KEY in server_keys:
            # nicknym server is authoritative for its own domain,
            # for other domains the key might come from key servers.
            validation_level = ValidationLevels.Weak_Chain
            _, domain = _split_email(address)
            if (domain == _get_domain(self._nickserver_uri)):
                validation_level = ValidationLevels.Provider_Trust

            yield self.put_raw_key(
                server_keys['openpgp'],
                OpenPGPKey,
                address=address,
                validation=validation_level)

    #
    # key management
    #

    def send_key(self, ktype):
        """
        Send user's key of type ktype to provider.

        Public key bound to user's is sent to provider, which will sign it and
        replace any prior keys for the same address in its database.

        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey

        :return: A Deferred which fires when the key is sent, or which fails
                 with KeyNotFound if the key was not found in local database.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)

        def send(pubkey):
            data = {
                self.PUBKEY_KEY: pubkey.key_data
            }
            uri = "%s/%s/users/%s.json" % (
                self._api_uri,
                self._api_version,
                self._uid)
            d = self._put(uri, data)
            d.addCallback(lambda _:
                          emit_async(catalog.KEYMANAGER_DONE_UPLOADING_KEYS,
                                     self._address))
            return d

        d = self.get_key(
            self._address, ktype, private=False, fetch_remote=False)
        d.addCallback(send)
        return d

    def get_key(self, address, ktype, private=False, fetch_remote=True):
        """
        Return a key of type ktype bound to address.

        First, search for the key in local storage. If it is not available,
        then try to fetch from nickserver.

        :param address: The address bound to the key.
        :type address: str
        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey
        :param private: Look for a private key instead of a public one?
        :type private: bool
        :param fetch_remote: If key not found in local storage try to fetch
                             from nickserver
        :type fetch_remote: bool

        :return: A Deferred which fires with an EncryptionKey of type ktype
                 bound to address, or which fails with KeyNotFound if no key
                 was found neither locally or in keyserver.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        logger.debug("getting key for %s" % (address,))
        leap_assert(
            ktype in self._wrapper_map,
            'Unkown key type: %s.' % str(ktype))
        _keys = self._wrapper_map[ktype]

        emit_async(catalog.KEYMANAGER_LOOKING_FOR_KEY, address)

        def key_found(key):
            emit_async(catalog.KEYMANAGER_KEY_FOUND, address)
            return key

        def key_not_found(failure):
            if not failure.check(KeyNotFound):
                return failure

            emit_async(catalog.KEYMANAGER_KEY_NOT_FOUND, address)

            # we will only try to fetch a key from nickserver if fetch_remote
            # is True and the key is not private.
            if fetch_remote is False or private is True:
                return failure

            emit_async(catalog.KEYMANAGER_LOOKING_FOR_KEY, address)
            d = self._fetch_keys_from_server(address)
            d.addCallback(
                lambda _: _keys.get_key(address, private=False))
            d.addCallback(key_found)
            return d

        # return key if it exists in local database
        d = _keys.get_key(address, private=private)
        d.addCallbacks(key_found, key_not_found)
        return d

    def get_all_keys(self, private=False):
        """
        Return all keys stored in local database.

        :param private: Include private keys
        :type private: bool

        :return: A Deferred which fires with a list of all keys in local db.
        :rtype: Deferred
        """
        # TODO: should it be based on activedocs?
        def build_keys(docs):
            return map(
                lambda doc: build_key_from_dict(
                    self._key_class_from_type(doc.content['type']),
                    doc.content),
                docs)

        # XXX: there is no check that the soledad indexes are ready, as it
        #      happens with EncryptionScheme.
        #      The usecases right now are not problematic. This could be solve
        #      adding a keytype to this funciont and moving the soledad request
        #      to the EncryptionScheme.
        d = self._soledad.get_from_index(
            TAGS_PRIVATE_INDEX,
            KEYMANAGER_KEY_TAG,
            '1' if private else '0')
        d.addCallback(build_keys)
        return d

    def gen_key(self, ktype):
        """
        Generate a key of type ktype bound to the user's address.

        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey

        :return: A Deferred which fires with the generated EncryptionKey.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        def signal_finished(key):
            emit_async(
                catalog.KEYMANAGER_FINISHED_KEY_GENERATION, self._address)
            return key

        emit_async(catalog.KEYMANAGER_STARTED_KEY_GENERATION, self._address)

        d = _keys.gen_key(self._address)
        d.addCallback(signal_finished)
        return d

    #
    # Setters/getters
    #

    def _get_token(self):
        return self._token

    def _set_token(self, token):
        self._token = token

    token = property(
        _get_token, _set_token, doc='The session token.')

    def _get_ca_cert_path(self):
        return self._ca_cert_path

    def _set_ca_cert_path(self, ca_cert_path):
        self._ca_cert_path = ca_cert_path

    ca_cert_path = property(
        _get_ca_cert_path, _set_ca_cert_path,
        doc='The path to the CA certificate.')

    def _get_api_uri(self):
        return self._api_uri

    def _set_api_uri(self, api_uri):
        self._api_uri = api_uri

    api_uri = property(
        _get_api_uri, _set_api_uri, doc='The webapp API URI.')

    def _get_api_version(self):
        return self._api_version

    def _set_api_version(self, api_version):
        self._api_version = api_version

    api_version = property(
        _get_api_version, _set_api_version, doc='The webapp API version.')

    def _get_uid(self):
        return self._uid

    def _set_uid(self, uid):
        self._uid = uid

    uid = property(
        _get_uid, _set_uid, doc='The uid of the user.')

    #
    # encrypt/decrypt and sign/verify API
    #

    def encrypt(self, data, address, ktype, passphrase=None, sign=None,
                cipher_algo='AES256', fetch_remote=True):
        """
        Encrypt data with the public key bound to address and sign with with
        the private key bound to sign address.

        :param data: The data to be encrypted.
        :type data: str
        :param address: The address to encrypt it for.
        :type address: str
        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey
        :param passphrase: The passphrase for the secret key used for the
                           signature.
        :type passphrase: str
        :param sign: The address to be used for signature.
        :type sign: str
        :param cipher_algo: The cipher algorithm to use.
        :type cipher_algo: str
        :param fetch_remote: If key is not found in local storage try to fetch
                             from nickserver
        :type fetch_remote: bool

        :return: A Deferred which fires with the encrypted data as str, or
                 which fails with KeyNotFound if no keys were found neither
                 locally or in keyserver or fails with EncryptError if failed
                 encrypting for some reason.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        @defer.inlineCallbacks
        def encrypt(keys):
            pubkey, signkey = keys
            encrypted = yield _keys.encrypt(
                data, pubkey, passphrase, sign=signkey,
                cipher_algo=cipher_algo)
            if not pubkey.encr_used:
                pubkey.encr_used = True
                yield _keys.put_key(pubkey)
            defer.returnValue(encrypted)

        dpub = self.get_key(address, ktype, private=False,
                            fetch_remote=fetch_remote)
        dpriv = defer.succeed(None)
        if sign is not None:
            dpriv = self.get_key(sign, ktype, private=True)
        d = defer.gatherResults([dpub, dpriv], consumeErrors=True)
        d.addCallbacks(encrypt, self._extract_first_error)
        return d

    def decrypt(self, data, address, ktype, passphrase=None, verify=None,
                fetch_remote=True):
        """
        Decrypt data using private key from address and verify with public key
        bound to verify address.

        :param data: The data to be decrypted.
        :type data: str
        :param address: The address to whom data was encrypted.
        :type address: str
        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey
        :param passphrase: The passphrase for the secret key used for
                           decryption.
        :type passphrase: str
        :param verify: The address to be used for signature.
        :type verify: str
        :param fetch_remote: If key for verify not found in local storage try
                             to fetch from nickserver
        :type fetch_remote: bool

        :return: A Deferred which fires with:
            * (decripted str, signing key) if validation works
            * (decripted str, KeyNotFound) if signing key not found
            * (decripted str, InvalidSignature) if signature is invalid
            * KeyNotFound failure if private key not found
            * DecryptError failure if decription failed
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        @defer.inlineCallbacks
        def decrypt(keys):
            pubkey, privkey = keys
            decrypted, signed = yield _keys.decrypt(
                data, privkey, passphrase=passphrase, verify=pubkey)
            if pubkey is None:
                signature = KeyNotFound(verify)
            elif signed:
                signature = pubkey
                if not pubkey.sign_used:
                    pubkey.sign_used = True
                    yield _keys.put_key(pubkey)
                    defer.returnValue((decrypted, signature))
            else:
                signature = InvalidSignature(
                    'Failed to verify signature with key %s' %
                    (pubkey.fingerprint,))
            defer.returnValue((decrypted, signature))

        dpriv = self.get_key(address, ktype, private=True)
        dpub = defer.succeed(None)
        if verify is not None:
            dpub = self.get_key(verify, ktype, private=False,
                                fetch_remote=fetch_remote)
            dpub.addErrback(lambda f: None if f.check(KeyNotFound) else f)
        d = defer.gatherResults([dpub, dpriv], consumeErrors=True)
        d.addCallbacks(decrypt, self._extract_first_error)
        return d

    def _extract_first_error(self, failure):
        return failure.value.subFailure

    def sign(self, data, address, ktype, digest_algo='SHA512', clearsign=False,
             detach=True, binary=False):
        """
        Sign data with private key bound to address.

        :param data: The data to be signed.
        :type data: str
        :param address: The address to be used to sign.
        :type address: EncryptionKey
        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey
        :param digest_algo: The hash digest to use.
        :type digest_algo: str
        :param clearsign: If True, create a cleartext signature.
        :type clearsign: bool
        :param detach: If True, create a detached signature.
        :type detach: bool
        :param binary: If True, do not ascii armour the output.
        :type binary: bool

        :return: A Deferred which fires with the signed data as str or fails
                 with KeyNotFound if no key was found neither locally or in
                 keyserver or fails with SignFailed if there was any error
                 signing.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        def sign(privkey):
            return _keys.sign(
                data, privkey, digest_algo=digest_algo, clearsign=clearsign,
                detach=detach, binary=binary)

        d = self.get_key(address, ktype, private=True)
        d.addCallback(sign)
        return d

    def verify(self, data, address, ktype, detached_sig=None,
               fetch_remote=True):
        """
        Verify signed data with private key bound to address, eventually using
        detached_sig.

        :param data: The data to be verified.
        :type data: str
        :param address: The address to be used to verify.
        :type address: EncryptionKey
        :param ktype: The type of the key.
        :type ktype: subclass of EncryptionKey
        :param detached_sig: A detached signature. If given, C{data} is
                             verified using this detached signature.
        :type detached_sig: str
        :param fetch_remote: If key for verify not found in local storage try
                             to fetch from nickserver
        :type fetch_remote: bool

        :return: A Deferred which fires with the signing EncryptionKey if
                 signature verifies, or which fails with InvalidSignature if
                 signature don't verifies or fails with KeyNotFound if no key
                 was found neither locally or in keyserver.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        def verify(pubkey):
            signed = _keys.verify(
                data, pubkey, detached_sig=detached_sig)
            if signed:
                if not pubkey.sign_used:
                    pubkey.sign_used = True
                    d = _keys.put_key(pubkey)
                    d.addCallback(lambda _: pubkey)
                    return d
                return pubkey
            else:
                raise InvalidSignature(
                    'Failed to verify signature with key %s' %
                    (pubkey.fingerprint,))

        d = self.get_key(address, ktype, private=False,
                         fetch_remote=fetch_remote)
        d.addCallback(verify)
        return d

    def delete_key(self, key):
        """
        Remove key from storage.

        :param key: The key to be removed.
        :type key: EncryptionKey

        :return: A Deferred which fires when the key is deleted, or which fails
                 KeyNotFound if the key was not found on local storage.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(type(key))
        _keys = self._wrapper_map[type(key)]
        return _keys.delete_key(key)

    def put_key(self, key):
        """
        Put key bound to address in local storage.

        :param key: The key to be stored
        :type key: EncryptionKey

        :return: A Deferred which fires when the key is in the storage, or
                 which fails with KeyNotValidUpdate if a key with the same
                 uid exists and the new one is not a valid update for it.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        ktype = type(key)
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        def old_key_not_found(failure):
            if failure.check(KeyNotFound):
                return None
            else:
                return failure

        def check_upgrade(old_key):
            if key.private or can_upgrade(key, old_key):
                return _keys.put_key(key)
            else:
                raise KeyNotValidUpgrade(
                    "Key %s can not be upgraded by new key %s"
                    % (old_key.fingerprint, key.fingerprint))

        d = _keys.get_key(key.address, private=key.private)
        d.addErrback(old_key_not_found)
        d.addCallback(check_upgrade)
        return d

    def put_raw_key(self, key, ktype, address,
                    validation=ValidationLevels.Weak_Chain):
        """
        Put raw key bound to address in local storage.

        :param key: The ascii key to be stored
        :type key: str
        :param ktype: the type of the key.
        :type ktype: subclass of EncryptionKey
        :param address: address for which this key will be active
        :type address: str
        :param validation: validation level for this key
                           (default: 'Weak_Chain')
        :type validation: ValidationLevels

        :return: A Deferred which fires when the key is in the storage, or
                 which fails with KeyAddressMismatch if address doesn't match
                 any uid on the key or fails with KeyNotFound if no OpenPGP
                 material was found in key or fails with KeyNotValidUpdate if a
                 key with the same uid exists and the new one is not a valid
                 update for it.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        pubkey, privkey = _keys.parse_ascii_key(key, address)

        if pubkey is None:
            return defer.fail(KeyNotFound(key))

        pubkey.validation = validation
        d = self.put_key(pubkey)
        if privkey is not None:
            d.addCallback(lambda _: self.put_key(privkey))
        return d

    @defer.inlineCallbacks
    def fetch_key(self, address, uri, ktype,
                  validation=ValidationLevels.Weak_Chain):
        """
        Fetch a public key bound to address from the network and put it in
        local storage.

        :param address: The email address of the key.
        :type address: str
        :param uri: The URI of the key.
        :type uri: str
        :param ktype: the type of the key.
        :type ktype: subclass of EncryptionKey
        :param validation: validation level for this key
                           (default: 'Weak_Chain')
        :type validation: ValidationLevels

        :return: A Deferred which fires when the key is in the storage, or
                 which fails with KeyNotFound: if not valid key on uri or fails
                 with KeyAddressMismatch if address doesn't match any uid on
                 the key or fails with KeyNotValidUpdate if a key with the same
                 uid exists and the new one is not a valid update for it.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        self._assert_supported_key_type(ktype)
        _keys = self._wrapper_map[ktype]

        logger.info("Fetch key for %s from %s" % (address, uri))
        ascii_content = yield self._get_with_combined_ca_bundle(uri)

        # XXX parse binary keys
        pubkey, _ = _keys.parse_ascii_key(ascii_content, address)
        if pubkey is None:
            raise KeyNotFound(uri)

        pubkey.validation = validation
        yield self.put_key(pubkey)

    def _assert_supported_key_type(self, ktype):
        """
        Check if ktype is one of the supported key types

        :param ktype: the type of the key.
        :type ktype: subclass of EncryptionKey

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        if ktype not in self._wrapper_map:
            raise UnsupportedKeyTypeError(str(ktype))


def _split_email(address):
    """
    Split username and domain from an email address

    :param address: an email address
    :type address: str

    :return: username and domain from the email address
    :rtype: (str, str)
    """
    if address.count("@") != 1:
        return None
    return address.split("@")


def _get_domain(url):
    """
    Get the domain from an url

    :param url: an url
    :type url: str

    :return: the domain part of the url
    :rtype: str
    """
    return urlparse(url).hostname
