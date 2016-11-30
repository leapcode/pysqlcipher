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
import fileinput
import json
import sys
import tempfile

from urlparse import urlparse

from twisted.logger import Logger
from twisted.internet import defer
from twisted.web import client
from twisted.web._responses import NOT_FOUND

from leap.common import ca_bundle
from leap.common.http import HTTPClient
from leap.common.events import emit_async, catalog

from leap.bitmask.keymanager import errors as keymanager_errors
from leap.bitmask.keymanager.errors import KeyNotFound
from leap.bitmask.keymanager.nicknym import Nicknym
from leap.bitmask.keymanager.refresher import RandomRefreshPublicKey
from leap.bitmask.keymanager.validation import ValidationLevels, can_upgrade
from leap.bitmask.keymanager.openpgp import OpenPGPScheme

logger = Logger()


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
                 gpgbinary=None, combined_ca_bundle=None):
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
        create = self._create_combined_bundle_file
        try:
            self._combined_ca_bundle = combined_ca_bundle or create()
        except Exception:
            logger.warn('error while creating combined ca bundle')
            self._combined_ca_bundle = ''

        self._async_client = HTTPClient(self._combined_ca_bundle)
        self._nicknym = Nicknym(self._nickserver_uri,
                                self._ca_cert_path, self._token)
        self.refresher = None
        self._init_gpg(soledad, gpgbinary)

    #
    # utilities
    #

    def _init_gpg(self, soledad, gpgbinary):
        self._openpgp = OpenPGPScheme(soledad, gpgbinary=gpgbinary)

    def start_refresher(self):
        self.refresher = RandomRefreshPublicKey(self._openpgp, self)
        self.refresher.start()

    def stop_refresher(self):
        self.refresher.stop()

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
            content = yield self._fetch_and_handle_404_from_nicknym(
                uri, address)
            json_content = json.loads(content)

        except keymanager_errors.KeyNotFound:
            raise
        except IOError as e:
            logger.warn("HTTP error retrieving key: %r" % (e,))
            logger.warn("%s" % (content,))
            raise keymanager_errors.KeyNotFound(e.message), \
                None, sys.exc_info()[2]
        except ValueError as v:
            logger.warn("invalid JSON data from key: %s" % (uri,))
            raise keymanager_errors.KeyNotFound(v.message + ' - ' + uri), \
                None, sys.exc_info()[2]

        except Exception as e:
            logger.warn("error retrieving key: %r" % (e,))
            raise keymanager_errors.KeyNotFound(e.message), \
                None, sys.exc_info()[2]
        # Responses are now text/plain, although it's json anyway, but
        # this will fail when it shouldn't
        # leap_assert(
        #     res.headers['content-type'].startswith('application/json'),
        #     'Content-type is not JSON.')
        defer.returnValue(json_content)

    def _fetch_and_handle_404_from_nicknym(self, uri, address):
        """
        Send a GET request to C{uri} containing C{data}.

        :param uri: The URI of the request.
        :type uri: str
        :param address: The email corresponding to the key.
        :type address: str

        :return: A deferred that will be fired with GET content as json (dict)
        :rtype: Deferred
        """
        def check_404(response):
            if response.code == NOT_FOUND:
                message = '%s: %s key not found.' % (response.code, address)
                logger.warn(message)
                raise KeyNotFound(message), None, sys.exc_info()[2]
            return response

        d = self._nicknym._async_client_pinned.request(
            str(uri), 'GET', callback=check_404)
        d.addCallback(client.readBody)
        return d

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
            logger.warn("There was a problem fetching key: %s" % (e,))
            raise keymanager_errors.KeyNotFound(uri)
        if not content:
            raise keymanager_errors.KeyNotFound(uri)
        defer.returnValue(content)

    #
    # key management
    #

    def send_key(self):
        """
        Send user's key to provider.

        Public key bound to user's is sent to provider, which will sign it and
        replace any prior keys for the same address in its database.

        :return: A Deferred which fires when the key is sent, or which fails
                 with KeyNotFound if the key was not found in local database.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        def send(pubkey):
            d = self._nicknym.put_key(self.uid, pubkey.key_data,
                                      self._api_uri, self._api_version)
            d.addCallback(lambda _:
                          emit_async(catalog.KEYMANAGER_DONE_UPLOADING_KEYS,
                                     self._address))
            return d

        d = self.get_key(
            self._address, private=False, fetch_remote=False)
        d.addCallback(send)
        return d

    @defer.inlineCallbacks
    def _fetch_keys_from_server_and_store_local(self, address):
        """
        Fetch keys  from nickserver and insert them in locale database.

        :param address: The address bound to the keys.
        :type address: str

        :return: A Deferred which fires when the key is in the storage,
                     or which fails with KeyNotFound if the key was not
                     found on nickserver.
        :rtype: Deferred

        """
        server_keys = yield self._nicknym.fetch_key_with_address(address)

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
            address=address,
            validation=validation_level)

    def get_key(self, address, private=False, fetch_remote=True):
        """
        Return a key bound to address.

        First, search for the key in local storage. If it is not available,
        then try to fetch from nickserver.

        :param address: The address bound to the key.
        :type address: str
        :param private: Look for a private key instead of a public one?
        :type private: bool
        :param fetch_remote: If key not found in local storage try to fetch
                             from nickserver
        :type fetch_remote: bool

        :return: A Deferred which fires with an EncryptionKey bound to address,
                 or which fails with KeyNotFound if no key was found neither
                 locally or in keyserver or fail with KeyVersionError if the
                 key has a format not supported by this version of KeyManager
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        logger.debug("getting key for %s" % (address,))

        emit_async(catalog.KEYMANAGER_LOOKING_FOR_KEY, address)

        def key_found(key):
            emit_async(catalog.KEYMANAGER_KEY_FOUND, address)
            return key

        def key_not_found(failure):
            if not failure.check(keymanager_errors.KeyNotFound):
                return failure

            emit_async(catalog.KEYMANAGER_KEY_NOT_FOUND, address)

            # we will only try to fetch a key from nickserver if fetch_remote
            # is True and the key is not private.
            if fetch_remote is False or private is True:
                return failure

            emit_async(catalog.KEYMANAGER_LOOKING_FOR_KEY, address)
            d = self._fetch_keys_from_server_and_store_local(address)
            d.addCallback(
                lambda _: self._openpgp.get_key(address, private=False))
            d.addCallback(key_found)
            return d

        # return key if it exists in local database
        d = self._openpgp.get_key(address, private=private)
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
        return self._openpgp.get_all_keys(private)

    def gen_key(self):
        """
        Generate a key bound to the user's address.

        :return: A Deferred which fires with the generated EncryptionKey.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """
        def signal_finished(key):
            emit_async(
                catalog.KEYMANAGER_FINISHED_KEY_GENERATION, self._address)
            return key

        emit_async(catalog.KEYMANAGER_STARTED_KEY_GENERATION, self._address)

        d = self._openpgp.gen_key(self._address)
        d.addCallback(signal_finished)
        return d

    #
    # Setters/getters
    #

    def _get_token(self):
        return self._token

    def _set_token(self, token):
        self._token = token
        self._nicknym.token = token

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

    def encrypt(self, data, address, passphrase=None, sign=None,
                cipher_algo='AES256', fetch_remote=True):
        """
        Encrypt data with the public key bound to address and sign with with
        the private key bound to sign address.

        :param data: The data to be encrypted.
        :type data: str
        :param address: The address to encrypt it for.
        :type address: str
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
                 locally or in keyserver or fails with KeyVersionError if the
                 key format is not supported or fails with EncryptError if
                 failed encrypting for some reason.
        :rtype: Deferred

        :raise UnsupportedKeyTypeError: if invalid key type
        """

        @defer.inlineCallbacks
        def encrypt(keys):
            pubkey, signkey = keys
            encrypted = yield self._openpgp.encrypt(
                data, pubkey, passphrase, sign=signkey,
                cipher_algo=cipher_algo)
            if not pubkey.encr_used:
                pubkey.encr_used = True
                yield self._openpgp.put_key(pubkey)
            defer.returnValue(encrypted)

        dpub = self.get_key(address, private=False,
                            fetch_remote=fetch_remote)
        dpriv = defer.succeed(None)
        if sign is not None:
            dpriv = self.get_key(sign, private=True)
        d = defer.gatherResults([dpub, dpriv], consumeErrors=True)
        d.addCallbacks(encrypt, self._extract_first_error)
        return d

    def decrypt(self, data, address, passphrase=None, verify=None,
                fetch_remote=True):
        """
        Decrypt data using private key from address and verify with public key
        bound to verify address.

        :param data: The data to be decrypted.
        :type data: str
        :param address: The address to whom data was encrypted.
        :type address: str
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

        @defer.inlineCallbacks
        def decrypt(keys):
            pubkey, privkey = keys
            decrypted, signed = yield self._openpgp.decrypt(
                data, privkey, passphrase=passphrase, verify=pubkey)
            if pubkey is None:
                signature = keymanager_errors.KeyNotFound(verify)
            elif signed:
                signature = pubkey
                if not pubkey.sign_used:
                    pubkey.sign_used = True
                    yield self._openpgp.put_key(pubkey)
                    defer.returnValue((decrypted, signature))
            else:
                signature = keymanager_errors.InvalidSignature(
                    'Failed to verify signature with key %s' %
                    (pubkey.fingerprint,))
            defer.returnValue((decrypted, signature))

        dpriv = self.get_key(address, private=True)
        dpub = defer.succeed(None)
        if verify is not None:
            dpub = self.get_key(verify, private=False,
                                fetch_remote=fetch_remote)
            dpub.addErrback(lambda f: None if f.check(
                keymanager_errors.KeyNotFound) else f)
        d = defer.gatherResults([dpub, dpriv], consumeErrors=True)
        d.addCallbacks(decrypt, self._extract_first_error)
        return d

    def _extract_first_error(self, failure):
        return failure.value.subFailure

    def sign(self, data, address, digest_algo='SHA512', clearsign=False,
             detach=True, binary=False):
        """
        Sign data with private key bound to address.

        :param data: The data to be signed.
        :type data: str
        :param address: The address to be used to sign.
        :type address: EncryptionKey
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

        def sign(privkey):
            return self._openpgp.sign(
                data, privkey, digest_algo=digest_algo, clearsign=clearsign,
                detach=detach, binary=binary)

        d = self.get_key(address, private=True)
        d.addCallback(sign)
        return d

    def verify(self, data, address, detached_sig=None,
               fetch_remote=True):
        """
        Verify signed data with private key bound to address, eventually using
        detached_sig.

        :param data: The data to be verified.
        :type data: str
        :param address: The address to be used to verify.
        :type address: EncryptionKey
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
        def verify(pubkey):
            signed = self._openpgp.verify(
                data, pubkey, detached_sig=detached_sig)
            if signed:
                if not pubkey.sign_used:
                    pubkey.sign_used = True
                    d = self._openpgp.put_key(pubkey)
                    d.addCallback(lambda _: pubkey)
                    return d
                return pubkey
            else:
                raise keymanager_errors.InvalidSignature(
                    'Failed to verify signature with key %s' %
                    (pubkey.fingerprint,))

        d = self.get_key(address, private=False,
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
        return self._openpgp.delete_key(key)

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
        def old_key_not_found(failure):
            if failure.check(keymanager_errors.KeyNotFound):
                return None
            else:
                return failure

        def check_upgrade(old_key):
            if key.private or can_upgrade(key, old_key):
                return self._openpgp.put_key(key)
            else:
                raise keymanager_errors.KeyNotValidUpgrade(
                    "Key %s can not be upgraded by new key %s"
                    % (old_key.fingerprint, key.fingerprint))

        d = self._openpgp.get_key(key.address, private=key.private)
        d.addErrback(old_key_not_found)
        d.addCallback(check_upgrade)
        return d

    def put_raw_key(self, key, address,
                    validation=ValidationLevels.Weak_Chain):
        """
        Put raw key bound to address in local storage.

        :param key: The ascii key to be stored
        :type key: str
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
        pubkey, privkey = self._openpgp.parse_key(key, address)

        if pubkey is None:
            return defer.fail(keymanager_errors.KeyNotFound(key))

        pubkey.validation = validation
        d = self.put_key(pubkey)
        if privkey is not None:
            d.addCallback(lambda _: self.put_key(privkey))
        return d

    @defer.inlineCallbacks
    def fetch_key(self, address, uri, validation=ValidationLevels.Weak_Chain):
        """
        Fetch a public key bound to address from the network and put it in
        local storage.

        :param address: The email address of the key.
        :type address: str
        :param uri: The URI of the key.
        :type uri: str
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

        logger.info("fetch key for %s from %s" % (address, uri))
        ascii_content = yield self._get_with_combined_ca_bundle(uri)

        # XXX parse binary keys
        pubkey, _ = self._openpgp.parse_key(ascii_content, address)
        if pubkey is None:
            raise keymanager_errors.KeyNotFound(uri)

        pubkey.validation = validation
        yield self.put_key(pubkey)

    def ever_synced(self):
        # TODO: provide this method in soledad api, avoid using a private
        # attribute here
        d = self._soledad._dbpool.runQuery('SELECT * FROM sync_log')
        d.addCallback(lambda result: bool(result))
        return d


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
