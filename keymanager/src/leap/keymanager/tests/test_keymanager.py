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


from mock import Mock
from leap.common.testing.basetest import BaseLeapTest
from leap.keymanager import (
    openpgp,
    KeyNotFound,
    KeyAddressMismatch,
    errors,
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
    KEY_FINGERPRINT,
    PUBLIC_KEY,
    PRIVATE_KEY,
    GPG_BINARY_PATH
)


ADDRESS_2 = 'anotheruser@leap.se'


class KeyManagerUtilTestCase(BaseLeapTest):

    def setUp(self):
        pass

    def tearDown(self):
        pass

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
            'address': ADDRESS,
            'key_id': 'key_id',
            'fingerprint': 'fingerprint',
            'key_data': 'key_data',
            'private': 'private',
            'length': 'length',
            'expiry_date': '',
            'first_seen_at': 'first_seen_at',
            'last_audited_at': 'last_audited_at',
            'validation': str(ValidationLevel.Weak_Chain),
        }
        key = build_key_from_dict(OpenPGPKey, ADDRESS, kdict)
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
            kdict['first_seen_at'], key.first_seen_at,
            'Wrong data in key.')
        self.assertEqual(
            kdict['last_audited_at'], key.last_audited_at,
            'Wrong data in key.')
        self.assertEqual(
            toValidationLevel(kdict['validation']), key.validation,
            'Wrong data in key.')


class OpenPGPCryptoTestCase(KeyManagerWithSoledadTestCase):

    def _test_openpgp_gen_key(self):
        pgp = openpgp.OpenPGPScheme(self._soledad)
        self.assertRaises(KeyNotFound, pgp.get_key, 'user@leap.se')
        key = pgp.gen_key('user@leap.se')
        self.assertIsInstance(key, openpgp.OpenPGPKey)
        self.assertEqual(
            'user@leap.se', key.address, 'Wrong address bound to key.')
        self.assertEqual(
            '4096', key.length, 'Wrong key length.')

    def test_openpgp_put_delete_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)
        pgp.put_ascii_key(PUBLIC_KEY)
        key = pgp.get_key(ADDRESS, private=False)
        pgp.delete_key(key)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)

    def test_openpgp_put_ascii_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)
        pgp.put_ascii_key(PUBLIC_KEY)
        key = pgp.get_key(ADDRESS, private=False)
        self.assertIsInstance(key, openpgp.OpenPGPKey)
        self.assertEqual(
            ADDRESS, key.address, 'Wrong address bound to key.')
        self.assertEqual(
            '4096', key.length, 'Wrong key length.')
        pgp.delete_key(key)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)

    def test_get_public_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)
        pgp.put_ascii_key(PUBLIC_KEY)
        self.assertRaises(
            KeyNotFound, pgp.get_key, ADDRESS, private=True)
        key = pgp.get_key(ADDRESS, private=False)
        self.assertEqual(ADDRESS, key.address)
        self.assertFalse(key.private)
        self.assertEqual(KEY_FINGERPRINT, key.fingerprint)
        pgp.delete_key(key)
        self.assertRaises(KeyNotFound, pgp.get_key, ADDRESS)

    def test_openpgp_encrypt_decrypt(self):
        # encrypt
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PUBLIC_KEY)
        pubkey = pgp.get_key(ADDRESS, private=False)
        cyphertext = pgp.encrypt('data', pubkey)
        # assert
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        self.assertTrue(pgp.is_encrypted(cyphertext))
        self.assertTrue(pgp.is_encrypted(cyphertext))
        # decrypt
        self.assertRaises(
            KeyNotFound, pgp.get_key, ADDRESS, private=True)
        pgp.put_ascii_key(PRIVATE_KEY)
        privkey = pgp.get_key(ADDRESS, private=True)
        pgp.delete_key(pubkey)
        pgp.delete_key(privkey)
        self.assertRaises(
            KeyNotFound, pgp.get_key, ADDRESS, private=False)
        self.assertRaises(
            KeyNotFound, pgp.get_key, ADDRESS, private=True)

    def test_verify_with_private_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey)
        self.assertRaises(
            AssertionError,
            pgp.verify, signed, privkey)

    def test_sign_with_public_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PUBLIC_KEY)
        data = 'data'
        pubkey = pgp.get_key(ADDRESS, private=False)
        self.assertRaises(
            AssertionError,
            pgp.sign, data, pubkey)

    def test_verify_with_wrong_key_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey)
        pgp.put_ascii_key(PUBLIC_KEY_2)
        wrongkey = pgp.get_key(ADDRESS_2)
        self.assertRaises(
            errors.InvalidSignature,
            pgp.verify, signed, wrongkey)

    def test_encrypt_sign_with_public_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        pubkey = pgp.get_key(ADDRESS, private=False)
        self.assertRaises(
            AssertionError,
            pgp.encrypt, data, privkey, sign=pubkey)

    def test_decrypt_verify_with_private_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        pubkey = pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = pgp.encrypt(
            data, pubkey, sign=privkey)
        self.assertRaises(
            AssertionError,
            pgp.decrypt,
            encrypted_and_signed, privkey, verify=privkey)

    def test_decrypt_verify_with_wrong_key_raises(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        pubkey = pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = pgp.encrypt(data, pubkey, sign=privkey)
        pgp.put_ascii_key(PUBLIC_KEY_2)
        wrongkey = pgp.get_key(ADDRESS_2)
        self.assertRaises(
            errors.InvalidSignature,
            pgp.verify, encrypted_and_signed, wrongkey)

    def test_sign_verify(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey, detach=False)
        pubkey = pgp.get_key(ADDRESS, private=False)
        self.assertTrue(pgp.verify(signed, pubkey))

    def test_encrypt_sign_decrypt_verify(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        pubkey = pgp.get_key(ADDRESS, private=False)
        privkey = pgp.get_key(ADDRESS, private=True)
        pgp.put_ascii_key(PRIVATE_KEY_2)
        pubkey2 = pgp.get_key(ADDRESS_2, private=False)
        privkey2 = pgp.get_key(ADDRESS_2, private=True)
        data = 'data'
        encrypted_and_signed = pgp.encrypt(
            data, pubkey2, sign=privkey)
        res = pgp.decrypt(
            encrypted_and_signed, privkey2, verify=pubkey)
        self.assertTrue(data, res)

    def test_sign_verify_detached_sig(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=GPG_BINARY_PATH)
        pgp.put_ascii_key(PRIVATE_KEY)
        data = 'data'
        privkey = pgp.get_key(ADDRESS, private=True)
        signature = pgp.sign(data, privkey, detach=True)
        pubkey = pgp.get_key(ADDRESS, private=False)
        self.assertTrue(pgp.verify(data, pubkey, detached_sig=signature))


class KeyManagerKeyManagementTestCase(KeyManagerWithSoledadTestCase):

    def test_get_all_keys_in_db(self):
        km = self._key_manager()
        km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY)
        # get public keys
        keys = km.get_all_keys(False)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertEqual(ADDRESS, keys[0].address)
        self.assertFalse(keys[0].private)
        # get private keys
        keys = km.get_all_keys(True)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertEqual(ADDRESS, keys[0].address)
        self.assertTrue(keys[0].private)

    def test_get_public_key(self):
        km = self._key_manager()
        km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY)
        # get the key
        key = km.get_key(ADDRESS, OpenPGPKey, private=False,
                         fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertEqual(key.address, ADDRESS)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertFalse(key.private)

    def test_get_private_key(self):
        km = self._key_manager()
        km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY)
        # get the key
        key = km.get_key(ADDRESS, OpenPGPKey, private=True,
                         fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertEqual(key.address, ADDRESS)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertTrue(key.private)

    def test_send_key_raises_key_not_found(self):
        km = self._key_manager()
        self.assertRaises(
            KeyNotFound,
            km.send_key, OpenPGPKey)

    def test_send_key(self):
        """
        Test that request is well formed when sending keys to server.
        """
        token = "mytoken"
        km = self._key_manager(token=token)
        km._wrapper_map[OpenPGPKey].put_ascii_key(PUBLIC_KEY)
        km._fetcher.put = Mock()
        # the following data will be used on the send
        km.ca_cert_path = 'capath'
        km.session_id = 'sessionid'
        km.uid = 'myuid'
        km.api_uri = 'apiuri'
        km.api_version = 'apiver'
        km.send_key(OpenPGPKey)
        # setup expected args
        data = {
            km.PUBKEY_KEY: km.get_key(km._address, OpenPGPKey).key_data,
        }
        url = '%s/%s/users/%s.json' % ('apiuri', 'apiver', 'myuid')
        km._fetcher.put.assert_called_once_with(
            url, data=data, verify='capath',
            headers={'Authorization': 'Token token=%s' % token},
        )

    def test__fetch_keys_from_server(self):
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
        # do the fetch
        km._fetch_keys_from_server(ADDRESS_2)
        # and verify the call
        km._fetcher.get.assert_called_once_with(
            'http://nickserver.domain',
            data={'address': ADDRESS_2},
            verify='cacertpath',
        )

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
        self.assertRaises(
            KeyNotFound, km.get_key, ADDRESS, OpenPGPKey,
            fetch_remote=False
        )
        # try to get key fetching from server.
        key = km.get_key(ADDRESS, OpenPGPKey)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertEqual(ADDRESS, key.address)

    def test_put_key_ascii(self):
        """
        Test that putting ascii key works
        """
        km = self._key_manager(url='http://nickserver.domain')

        km.put_raw_key(PUBLIC_KEY, OpenPGPKey)
        key = km.get_key(ADDRESS, OpenPGPKey)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertEqual(ADDRESS, key.address)

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

        km.fetch_key(ADDRESS, "http://site.domain/key", OpenPGPKey)
        key = km.get_key(ADDRESS, OpenPGPKey)
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
        self.assertRaises(KeyNotFound, km.fetch_key,
                          ADDRESS, "http://site.domain/key", OpenPGPKey)

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
        self.assertRaises(KeyAddressMismatch, km.fetch_key,
                          ADDRESS_2, "http://site.domain/key", OpenPGPKey)


class KeyManagerCryptoTestCase(KeyManagerWithSoledadTestCase):

    RAW_DATA = 'data'

    def test_keymanager_openpgp_encrypt_decrypt(self):
        km = self._key_manager()
        # put raw private key
        km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY)
        # get public key
        pubkey = km.get_key(
            ADDRESS, OpenPGPKey, private=False, fetch_remote=False)
        # encrypt
        encdata = km.encrypt(self.RAW_DATA, pubkey)
        self.assertNotEqual(self.RAW_DATA, encdata)
        # get private key
        privkey = km.get_key(
            ADDRESS, OpenPGPKey, private=True, fetch_remote=False)
        # decrypt
        rawdata = km.decrypt(encdata, privkey)
        self.assertEqual(self.RAW_DATA, rawdata)

    def test_keymanager_openpgp_sign_verify(self):
        km = self._key_manager()
        # put raw private keys
        km._wrapper_map[OpenPGPKey].put_ascii_key(PRIVATE_KEY)
        # get private key for signing
        privkey = km.get_key(
            ADDRESS, OpenPGPKey, private=True, fetch_remote=False)
        # encrypt
        signdata = km.sign(self.RAW_DATA, privkey, detach=False)
        self.assertNotEqual(self.RAW_DATA, signdata)
        # get public key for verifying
        pubkey = km.get_key(
            ADDRESS, OpenPGPKey, private=False, fetch_remote=False)
        # decrypt
        self.assertTrue(km.verify(signdata, pubkey))


# Key material for testing

# key 7FEE575A: public key "anotheruser <anotheruser@leap.se>"
PUBLIC_KEY_2 = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)

mI0EUYwJXgEEAMbTKHuPJ5/Gk34l9Z06f+0WCXTDXdte1UBoDtZ1erAbudgC4MOR
gquKqoj3Hhw0/ILqJ88GcOJmKK/bEoIAuKaqlzDF7UAYpOsPZZYmtRfPC2pTCnXq
Z1vdeqLwTbUspqXflkCkFtfhGKMq5rH8GV5a3tXZkRWZhdNwhVXZagC3ABEBAAG0
IWFub3RoZXJ1c2VyIDxhbm90aGVydXNlckBsZWFwLnNlPoi4BBMBAgAiBQJRjAle
AhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRB/nfpof+5XWotuA/4tLN4E
gUr7IfLy2HkHAxzw7A4rqfMN92DIM9mZrDGaWRrOn3aVF7VU1UG7MDkHfPvp/cFw
ezoCw4s4IoHVc/pVlOkcHSyt4/Rfh248tYEJmFCJXGHpkK83VIKYJAithNccJ6Q4
JE/o06Mtf4uh/cA1HUL4a4ceqUhtpLJULLeKo7iNBFGMCV4BBADsyQI7GR0wSAxz
VayLjuPzgT+bjbFeymIhjuxKIEwnIKwYkovztW+4bbOcQs785k3Lp6RzvigTpQQt
Z/hwcLOqZbZw8t/24+D+Pq9mMP2uUvCFFqLlVvA6D3vKSQ/XNN+YB919WQ04jh63
yuRe94WenT1RJd6xU1aaUff4rKizuQARAQABiJ8EGAECAAkFAlGMCV4CGwwACgkQ
f536aH/uV1rPZQQAqCzRysOlu8ez7PuiBD4SebgRqWlxa1TF1ujzfLmuPivROZ2X
Kw5aQstxgGSjoB7tac49s0huh4X8XK+BtJBfU84JS8Jc2satlfwoyZ35LH6sDZck
I+RS/3we6zpMfHs3vvp9xgca6ZupQxivGtxlJs294TpJorx+mFFqbV17AzQ=
=Thdu
-----END PGP PUBLIC KEY BLOCK-----
"""

PRIVATE_KEY_2 = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)

lQHYBFGMCV4BBADG0yh7jyefxpN+JfWdOn/tFgl0w13bXtVAaA7WdXqwG7nYAuDD
kYKriqqI9x4cNPyC6ifPBnDiZiiv2xKCALimqpcwxe1AGKTrD2WWJrUXzwtqUwp1
6mdb3Xqi8E21LKal35ZApBbX4RijKuax/BleWt7V2ZEVmYXTcIVV2WoAtwARAQAB
AAP7BLuSAx7tOohnimEs74ks8l/L6dOcsFQZj2bqs4AoY3jFe7bV0tHr4llypb/8
H3/DYvpf6DWnCjyUS1tTnXSW8JXtx01BUKaAufSmMNg9blKV6GGHlT/Whe9uVyks
7XHk/+9mebVMNJ/kNlqq2k+uWqJohzC8WWLRK+d1tBeqDsECANZmzltPaqUsGV5X
C3zszE3tUBgptV/mKnBtopKi+VH+t7K6fudGcG+bAcZDUoH/QVde52mIIjjIdLje
uajJuHUCAO1mqh+vPoGv4eBLV7iBo3XrunyGXiys4a39eomhxTy3YktQanjjx+ty
GltAGCs5PbWGO6/IRjjvd46wh53kzvsCAO0J97gsWhzLuFnkxFAJSPk7RRlyl7lI
1XS/x0Og6j9XHCyY1OYkfBm0to3UlCfkgirzCYlTYObCofzdKFIPDmSqHbQhYW5v
dGhlcnVzZXIgPGFub3RoZXJ1c2VyQGxlYXAuc2U+iLgEEwECACIFAlGMCV4CGwMG
CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEH+d+mh/7ldai24D/i0s3gSBSvsh
8vLYeQcDHPDsDiup8w33YMgz2ZmsMZpZGs6fdpUXtVTVQbswOQd8++n9wXB7OgLD
izgigdVz+lWU6RwdLK3j9F+Hbjy1gQmYUIlcYemQrzdUgpgkCK2E1xwnpDgkT+jT
oy1/i6H9wDUdQvhrhx6pSG2kslQst4qjnQHYBFGMCV4BBADsyQI7GR0wSAxzVayL
juPzgT+bjbFeymIhjuxKIEwnIKwYkovztW+4bbOcQs785k3Lp6RzvigTpQQtZ/hw
cLOqZbZw8t/24+D+Pq9mMP2uUvCFFqLlVvA6D3vKSQ/XNN+YB919WQ04jh63yuRe
94WenT1RJd6xU1aaUff4rKizuQARAQABAAP9EyElqJ3dq3EErXwwT4mMnbd1SrVC
rUJrNWQZL59mm5oigS00uIyR0SvusOr+UzTtd8ysRuwHy5d/LAZsbjQStaOMBILx
77TJveOel0a1QK0YSMF2ywZMCKvquvjli4hAtWYz/EwfuzQN3t23jc5ny+GqmqD2
3FUxLJosFUfLNmECAO9KhVmJi+L9dswIs+2Dkjd1eiRQzNOEVffvYkGYZyKxNiXF
UA5kvyZcB4iAN9sWCybE4WHZ9jd4myGB0MPDGxkCAP1RsXJbbuD6zS7BXe5gwunO
2q4q7ptdSl/sJYQuTe1KNP5d/uGsvlcFfsYjpsopasPjFBIncc/2QThMKlhoEaEB
/0mVAxpT6SrEvUbJ18z7kna24SgMPr3OnPMxPGfvNLJY/Xv/A17YfoqjmByCvsKE
JCDjopXtmbcrZyoEZbEht9mko4ifBBgBAgAJBQJRjAleAhsMAAoJEH+d+mh/7lda
z2UEAKgs0crDpbvHs+z7ogQ+Enm4EalpcWtUxdbo83y5rj4r0TmdlysOWkLLcYBk
o6Ae7WnOPbNIboeF/FyvgbSQX1POCUvCXNrGrZX8KMmd+Sx+rA2XJCPkUv98Hus6
THx7N776fcYHGumbqUMYrxrcZSbNveE6SaK8fphRam1dewM0
=a5gs
-----END PGP PRIVATE KEY BLOCK-----
"""
import unittest
if __name__ == "__main__":
    unittest.main()
