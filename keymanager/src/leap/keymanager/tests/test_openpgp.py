# -*- coding: utf-8 -*-
# test_keymanager.py
# Copyright (C) 2014 LEAP
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
Tests for the OpenPGP support on Key Manager.
"""


from datetime import datetime
from mock import Mock
from twisted.internet.defer import inlineCallbacks, gatherResults, succeed

from leap.keymanager import (
    KeyNotFound,
    openpgp,
)
from leap.keymanager.keys import TYPE_ID_PRIVATE_INDEX
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.tests import (
    KeyManagerWithSoledadTestCase,
    ADDRESS,
    ADDRESS_2,
    KEY_FINGERPRINT,
    PUBLIC_KEY,
    KEY_ID,
    PUBLIC_KEY_2,
    PRIVATE_KEY,
    PRIVATE_KEY_2,
)


class OpenPGPCryptoTestCase(KeyManagerWithSoledadTestCase):

    # set the trial timeout to 20min, needed by the key generation test
    timeout = 1200

    @inlineCallbacks
    def _test_openpgp_gen_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield self._assert_key_not_found(pgp, 'user@leap.se')
        key = yield pgp.gen_key('user@leap.se')
        self.assertIsInstance(key, openpgp.OpenPGPKey)
        self.assertEqual(
            ['user@leap.se'], key.address, 'Wrong address bound to key.')
        self.assertEqual(
            4096, key.length, 'Wrong key length.')

    @inlineCallbacks
    def test_openpgp_put_delete_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield self._assert_key_not_found(pgp, ADDRESS)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
        key = yield pgp.get_key(ADDRESS, private=False)
        yield pgp.delete_key(key)
        yield self._assert_key_not_found(pgp, ADDRESS)

    @inlineCallbacks
    def test_openpgp_put_ascii_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield self._assert_key_not_found(pgp, ADDRESS)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
        key = yield pgp.get_key(ADDRESS, private=False)
        self.assertIsInstance(key, openpgp.OpenPGPKey)
        self.assertTrue(
            ADDRESS in key.address, 'Wrong address bound to key.')
        self.assertEqual(
            4096, key.length, 'Wrong key length.')
        yield pgp.delete_key(key)
        yield self._assert_key_not_found(pgp, ADDRESS)

    @inlineCallbacks
    def test_get_public_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield self._assert_key_not_found(pgp, ADDRESS)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
        yield self._assert_key_not_found(pgp, ADDRESS, private=True)
        key = yield pgp.get_key(ADDRESS, private=False)
        self.assertTrue(ADDRESS in key.address)
        self.assertFalse(key.private)
        self.assertEqual(KEY_FINGERPRINT, key.fingerprint)
        yield pgp.delete_key(key)
        yield self._assert_key_not_found(pgp, ADDRESS)

    @inlineCallbacks
    def test_openpgp_encrypt_decrypt(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        # encrypt
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        cyphertext = pgp.encrypt(data, pubkey)

        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != data)
        self.assertTrue(pgp.is_encrypted(cyphertext))
        self.assertTrue(pgp.is_encrypted(cyphertext))

        # decrypt
        yield self._assert_key_not_found(pgp, ADDRESS, private=True)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        decrypted, _ = pgp.decrypt(cyphertext, privkey)
        self.assertEqual(decrypted, data)

        yield pgp.delete_key(pubkey)
        yield pgp.delete_key(privkey)
        yield self._assert_key_not_found(pgp, ADDRESS, private=False)
        yield self._assert_key_not_found(pgp, ADDRESS, private=True)

    @inlineCallbacks
    def test_verify_with_private_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey)
        self.assertRaises(
            AssertionError,
            pgp.verify, signed, privkey)

    @inlineCallbacks
    def test_sign_with_public_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
        self.assertRaises(
            AssertionError,
            pgp.sign, data, ADDRESS, OpenPGPKey)

    @inlineCallbacks
    def test_verify_with_wrong_key_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey)
        yield pgp.put_ascii_key(PUBLIC_KEY_2, ADDRESS_2)
        wrongkey = yield pgp.get_key(ADDRESS_2)
        self.assertFalse(pgp.verify(signed, wrongkey))

    @inlineCallbacks
    def test_encrypt_sign_with_public_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        self.assertRaises(
            AssertionError,
            pgp.encrypt, data, privkey, sign=pubkey)

    @inlineCallbacks
    def test_decrypt_verify_with_private_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = pgp.encrypt(
            data, pubkey, sign=privkey)
        self.assertRaises(
            AssertionError,
            pgp.decrypt,
            encrypted_and_signed, privkey, verify=privkey)

    @inlineCallbacks
    def test_decrypt_verify_with_wrong_key(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = pgp.encrypt(data, pubkey, sign=privkey)
        yield pgp.put_ascii_key(PUBLIC_KEY_2, ADDRESS_2)
        wrongkey = yield pgp.get_key(ADDRESS_2)
        decrypted, validsign = pgp.decrypt(encrypted_and_signed, privkey,
                                           verify=wrongkey)
        self.assertEqual(decrypted, data)
        self.assertFalse(validsign)

    @inlineCallbacks
    def test_sign_verify(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey, detach=False)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        validsign = pgp.verify(signed, pubkey)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_encrypt_sign_decrypt_verify(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        privkey = yield pgp.get_key(ADDRESS, private=True)

        yield pgp.put_ascii_key(PRIVATE_KEY_2, ADDRESS_2)
        pubkey2 = yield pgp.get_key(ADDRESS_2, private=False)
        privkey2 = yield pgp.get_key(ADDRESS_2, private=True)

        data = 'data'
        encrypted_and_signed = pgp.encrypt(
            data, pubkey2, sign=privkey)
        res, validsign = pgp.decrypt(
            encrypted_and_signed, privkey2, verify=pubkey)
        self.assertEqual(data, res)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_sign_verify_detached_sig(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signature = yield pgp.sign(data, privkey, detach=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        validsign = pgp.verify(data, pubkey, detached_sig=signature)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_self_repair_three_keys(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)

        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc

        def my_get_from_index(*args):
            if (args[0] == TYPE_ID_PRIVATE_INDEX and
                    args[2] == KEY_ID):
                k1 = OpenPGPKey(ADDRESS, key_id="1",
                                refreshed_at=datetime(2005, 1, 1))
                k2 = OpenPGPKey(ADDRESS, key_id="2",
                                refreshed_at=datetime(2007, 1, 1))
                k3 = OpenPGPKey(ADDRESS, key_id="3",
                                refreshed_at=datetime(2001, 1, 1))
                d1 = self._soledad.create_doc_from_json(k1.get_json())
                d2 = self._soledad.create_doc_from_json(k2.get_json())
                d3 = self._soledad.create_doc_from_json(k3.get_json())
                return gatherResults([d1, d2, d3])
            return get_from_index(*args)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))

        key = yield pgp.get_key(ADDRESS, private=False)

        try:
            self.assertEqual(key.key_id, "2")
            self.assertEqual(self._soledad.delete_doc.call_count, 2)
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc

    @inlineCallbacks
    def test_self_repair_no_keys(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)

        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc

        def my_get_from_index(*args):
            if (args[0] == TYPE_ID_PRIVATE_INDEX and
                    args[2] == KEY_ID):
                return succeed([])
            return get_from_index(*args)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))

        try:
            yield self.assertFailure(pgp.get_key(ADDRESS, private=False),
                                     KeyNotFound)
            self.assertEqual(self._soledad.delete_doc.call_count, 1)
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc

    @inlineCallbacks
    def test_self_repair_put_keys(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc

        def my_get_from_index(*args):
            if (args[0] == TYPE_ID_PRIVATE_INDEX and
                    args[2] == KEY_ID):
                k1 = OpenPGPKey(ADDRESS, key_id="1",
                                fingerprint=KEY_FINGERPRINT,
                                refreshed_at=datetime(2005, 1, 1))
                k2 = OpenPGPKey(ADDRESS, key_id="2",
                                fingerprint=KEY_FINGERPRINT,
                                refreshed_at=datetime(2007, 1, 1))
                k3 = OpenPGPKey(ADDRESS, key_id="3",
                                fingerprint=KEY_FINGERPRINT,
                                refreshed_at=datetime(2001, 1, 1))
                d1 = self._soledad.create_doc_from_json(k1.get_json())
                d2 = self._soledad.create_doc_from_json(k2.get_json())
                d3 = self._soledad.create_doc_from_json(k3.get_json())
                return gatherResults([d1, d2, d3])
            return get_from_index(*args)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))

        try:
            yield pgp.put_ascii_key(PUBLIC_KEY, ADDRESS)
            self.assertEqual(self._soledad.delete_doc.call_count, 2)
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc

    def _assert_key_not_found(self, pgp, address, private=False):
        d = pgp.get_key(address, private=private)
        return self.assertFailure(d, KeyNotFound)
