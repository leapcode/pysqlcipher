# -*- coding: utf-8 -*-
# test_keymanager.py
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
Tests for the Key Manager.
"""


from datetime import datetime
from mock import Mock
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest

from leap.keymanager import (
    KeyNotFound,
    KeyAddressMismatch,
    errors
)
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.keys import (
    is_address,
    build_key_from_dict,
)
from leap.keymanager.validation import (
    ValidationLevel,
    toValidationLevel
)
from leap.keymanager.tests import (
    KeyManagerWithSoledadTestCase,
    ADDRESS,
    ADDRESS_2,
    KEY_FINGERPRINT,
    PUBLIC_KEY,
    PUBLIC_KEY_2,
    PRIVATE_KEY,
    PRIVATE_KEY_2,
)


class KeyManagerUtilTestCase(unittest.TestCase):

    def test_is_address(self):
        self.assertTrue(
            is_address('user@leap.se'),
            'Incorrect address detection.')
        self.assertFalse(
            is_address('userleap.se'),
            'Incorrect address detection.')
        self.assertFalse(
            is_address('user@'),
            'Incorrect address detection.')
        self.assertFalse(
            is_address('@leap.se'),
            'Incorrect address detection.')

    def test_build_key_from_dict(self):
        kdict = {
            'address': [ADDRESS],
            'key_id': KEY_FINGERPRINT[-16:],
            'fingerprint': KEY_FINGERPRINT,
            'key_data': PUBLIC_KEY,
            'private': False,
            'length': 4096,
            'expiry_date': 0,
            'last_audited_at': 0,
            'refreshed_at': 1311239602,
            'validation': str(ValidationLevel.Weak_Chain),
            'encr_used': False,
            'sign_used': True,
        }
        key = build_key_from_dict(OpenPGPKey, kdict)
        self.assertEqual(
            kdict['address'], key.address,
            'Wrong data in key.')
        self.assertEqual(
            kdict['key_id'], key.key_id,
            'Wrong data in key.')
        self.assertEqual(
            kdict['fingerprint'], key.fingerprint,
            'Wrong data in key.')
        self.assertEqual(
            kdict['key_data'], key.key_data,
            'Wrong data in key.')
        self.assertEqual(
            kdict['private'], key.private,
            'Wrong data in key.')
        self.assertEqual(
            kdict['length'], key.length,
            'Wrong data in key.')
        self.assertEqual(
            None, key.expiry_date,
            'Wrong data in key.')
        self.assertEqual(
            None, key.last_audited_at,
            'Wrong data in key.')
        self.assertEqual(
            datetime.fromtimestamp(kdict['refreshed_at']), key.refreshed_at,
            'Wrong data in key.')
        self.assertEqual(
            toValidationLevel(kdict['validation']), key.validation,
            'Wrong data in key.')
        self.assertEqual(
            kdict['encr_used'], key.encr_used,
            'Wrong data in key.')
        self.assertEqual(
            kdict['sign_used'], key.sign_used,
            'Wrong data in key.')


class KeyManagerKeyManagementTestCase(KeyManagerWithSoledadTestCase):

    @inlineCallbacks
    def test_get_all_keys_in_db(self):
        km = self._key_manager()
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        # get public keys
        keys = yield km.get_all_keys(False)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertTrue(ADDRESS in keys[0].address)
        self.assertFalse(keys[0].private)
        # get private keys
        keys = yield km.get_all_keys(True)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertTrue(ADDRESS in keys[0].address)
        self.assertTrue(keys[0].private)

    @inlineCallbacks
    def test_get_public_key(self):
        km = self._key_manager()
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        # get the key
        key = yield km.get_key(ADDRESS, OpenPGPKey, private=False,
                               fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertTrue(ADDRESS in key.address)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertFalse(key.private)

    @inlineCallbacks
    def test_get_private_key(self):
        km = self._key_manager()
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        # get the key
        key = yield km.get_key(ADDRESS, OpenPGPKey, private=True,
                               fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertTrue(ADDRESS in key.address)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertTrue(key.private)

    def test_send_key_raises_key_not_found(self):
        km = self._key_manager()
        d = km.send_key(OpenPGPKey)
        return self.assertFailure(d, KeyNotFound)

    @inlineCallbacks
    def test_send_key(self):
        """
        Test that request is well formed when sending keys to server.
        """
        token = "mytoken"
        km = self._key_manager(token=token)
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PUBLIC_KEY, ADDRESS)
        km._fetcher.put = Mock()
        # the following data will be used on the send
        km.ca_cert_path = 'capath'
        km.session_id = 'sessionid'
        km.uid = 'myuid'
        km.api_uri = 'apiuri'
        km.api_version = 'apiver'
        yield km.send_key(OpenPGPKey)
        # setup expected args
        pubkey = yield km.get_key(km._address, OpenPGPKey)
        data = {
            km.PUBKEY_KEY: pubkey.key_data,
        }
        url = '%s/%s/users/%s.json' % ('apiuri', 'apiver', 'myuid')
        km._fetcher.put.assert_called_once_with(
            url, data=data, verify='capath',
            headers={'Authorization': 'Token token=%s' % token},
        )

    def test_fetch_keys_from_server(self):
        """
        Test that the request is well formed when fetching keys from server.
        """
        km = self._key_manager(url='http://nickserver.domain')

        class Response(object):
            status_code = 200
            headers = {'content-type': 'application/json'}

            def json(self):
                return {'address': ADDRESS_2, 'openpgp': PUBLIC_KEY_2}

            def raise_for_status(self):
                pass

        # mock the fetcher so it returns the key for ADDRESS_2
        km._fetcher.get = Mock(
            return_value=Response())
        km.ca_cert_path = 'cacertpath'

        def verify_the_call(_):
            km._fetcher.get.assert_called_once_with(
                'http://nickserver.domain',
                data={'address': ADDRESS_2},
                verify='cacertpath',
            )

        d = km._fetch_keys_from_server(ADDRESS_2)
        d.addCallback(verify_the_call)
        return d

    @inlineCallbacks
    def test_get_key_fetches_from_server(self):
        """
        Test that getting a key successfuly fetches from server.
        """
        km = self._key_manager(url='http://nickserver.domain')

        class Response(object):
            status_code = 200
            headers = {'content-type': 'application/json'}

            def json(self):
                return {'address': ADDRESS, 'openpgp': PUBLIC_KEY}

            def raise_for_status(self):
                pass

        # mock the fetcher so it returns the key for ADDRESS_2
        km._fetcher.get = Mock(return_value=Response())
        km.ca_cert_path = 'cacertpath'
        # try to key get without fetching from server
        d = km.get_key(ADDRESS, OpenPGPKey, fetch_remote=False)
        yield self.assertFailure(d, KeyNotFound)
        # try to get key fetching from server.
        key = yield km.get_key(ADDRESS, OpenPGPKey)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS in key.address)

    @inlineCallbacks
    def test_put_key_ascii(self):
        """
        Test that putting ascii key works
        """
        km = self._key_manager(url='http://nickserver.domain')

        yield km.put_raw_key(PUBLIC_KEY, OpenPGPKey, ADDRESS)
        key = yield km.get_key(ADDRESS, OpenPGPKey)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS in key.address)

    @inlineCallbacks
    def test_fetch_uri_ascii_key(self):
        """
        Test that fetch key downloads the ascii key and gets included in
        the local storage
        """
        km = self._key_manager()

        class Response(object):
            ok = True
            content = PUBLIC_KEY

        km._fetcher.get = Mock(return_value=Response())
        km.ca_cert_path = 'cacertpath'

        yield km.fetch_key(ADDRESS, "http://site.domain/key", OpenPGPKey)
        key = yield km.get_key(ADDRESS, OpenPGPKey)
        self.assertEqual(KEY_FINGERPRINT, key.fingerprint)

    def test_fetch_uri_empty_key(self):
        """
        Test that fetch key raises KeyNotFound if no key in the url
        """
        km = self._key_manager()

        class Response(object):
            ok = True
            content = ""

        km._fetcher.get = Mock(return_value=Response())
        km.ca_cert_path = 'cacertpath'
        d = km.fetch_key(ADDRESS, "http://site.domain/key", OpenPGPKey)
        return self.assertFailure(d, KeyNotFound)

    def test_fetch_uri_address_differ(self):
        """
        Test that fetch key raises KeyAttributesDiffer if the address
        don't match
        """
        km = self._key_manager()

        class Response(object):
            ok = True
            content = PUBLIC_KEY

        km._fetcher.get = Mock(return_value=Response())
        km.ca_cert_path = 'cacertpath'
        d = km.fetch_key(ADDRESS_2, "http://site.domain/key", OpenPGPKey)
        return self.assertFailure(d, KeyAddressMismatch)


class KeyManagerCryptoTestCase(KeyManagerWithSoledadTestCase):

    RAW_DATA = 'data'

    @inlineCallbacks
    def test_keymanager_openpgp_encrypt_decrypt(self):
        km = self._key_manager()
        # put raw private key
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(
            PRIVATE_KEY_2, ADDRESS_2)
        # encrypt
        encdata = yield km.encrypt(self.RAW_DATA, ADDRESS, OpenPGPKey,
                                   sign=ADDRESS_2, fetch_remote=False)
        self.assertNotEqual(self.RAW_DATA, encdata)
        # decrypt
        rawdata, signingkey = yield km.decrypt(
            encdata, ADDRESS, OpenPGPKey, verify=ADDRESS_2, fetch_remote=False)
        self.assertEqual(self.RAW_DATA, rawdata)
        key = yield km.get_key(ADDRESS_2, OpenPGPKey, private=False,
                               fetch_remote=False)
        self.assertEqual(signingkey.fingerprint, key.fingerprint)

    @inlineCallbacks
    def test_keymanager_openpgp_encrypt_decrypt_wrong_sign(self):
        km = self._key_manager()
        # put raw keys
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(
            PRIVATE_KEY_2, ADDRESS_2)
        # encrypt
        encdata = yield km.encrypt(self.RAW_DATA, ADDRESS, OpenPGPKey,
                                   sign=ADDRESS_2, fetch_remote=False)
        self.assertNotEqual(self.RAW_DATA, encdata)
        # verify
        rawdata, signingkey = yield km.decrypt(
            encdata, ADDRESS, OpenPGPKey, verify=ADDRESS, fetch_remote=False)
        self.assertEqual(self.RAW_DATA, rawdata)
        self.assertTrue(isinstance(signingkey, errors.InvalidSignature))

    @inlineCallbacks
    def test_keymanager_openpgp_sign_verify(self):
        km = self._key_manager()
        # put raw private keys
        yield km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY, ADDRESS)
        signdata = yield km.sign(self.RAW_DATA, ADDRESS, OpenPGPKey,
                                 detach=False)
        self.assertNotEqual(self.RAW_DATA, signdata)
        # verify
        signingkey = yield km.verify(signdata, ADDRESS, OpenPGPKey,
                                     fetch_remote=False)
        key = yield km.get_key(ADDRESS, OpenPGPKey, private=False,
                               fetch_remote=False)
        self.assertEqual(signingkey.fingerprint, key.fingerprint)


import unittest
if __name__ == "__main__":
    unittest.main()
