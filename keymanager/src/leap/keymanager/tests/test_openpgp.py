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
from leap.keymanager.keys import (
    TYPE_FINGERPRINT_PRIVATE_INDEX,
    TYPE_ADDRESS_PRIVATE_INDEX,
)
from leap.keymanager.keys import OpenPGPKey
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
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
        key = yield pgp.get_key(ADDRESS, private=False)
        yield pgp.delete_key(key)
        yield self._assert_key_not_found(pgp, ADDRESS)

    @inlineCallbacks
    def test_openpgp_put_ascii_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield self._assert_key_not_found(pgp, ADDRESS)
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
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
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
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
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        cyphertext = yield pgp.encrypt(data, pubkey)

        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != data)
        self.assertTrue(pgp.is_encrypted(cyphertext))
        self.assertTrue(pgp.is_encrypted(cyphertext))

        # decrypt
        yield self._assert_key_not_found(pgp, ADDRESS, private=True)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        decrypted, _ = yield pgp.decrypt(cyphertext, privkey)
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
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
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
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
        self.assertRaises(
            AssertionError,
            pgp.sign, data, ADDRESS, OpenPGPKey)

    @inlineCallbacks
    def test_verify_with_wrong_key_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey)
        yield pgp.put_raw_key(PUBLIC_KEY_2, ADDRESS_2)
        wrongkey = yield pgp.get_key(ADDRESS_2)
        self.assertFalse(pgp.verify(signed, wrongkey))

    @inlineCallbacks
    def test_encrypt_sign_with_public_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        self.failureResultOf(
            pgp.encrypt(data, privkey, sign=pubkey),
            AssertionError)

    @inlineCallbacks
    def test_decrypt_verify_with_private_raises(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = yield pgp.encrypt(
            data, pubkey, sign=privkey)
        self.failureResultOf(
            pgp.decrypt(encrypted_and_signed, privkey, verify=privkey),
            AssertionError)

    @inlineCallbacks
    def test_decrypt_verify_with_wrong_key(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        encrypted_and_signed = yield pgp.encrypt(data, pubkey, sign=privkey)
        yield pgp.put_raw_key(PUBLIC_KEY_2, ADDRESS_2)
        wrongkey = yield pgp.get_key(ADDRESS_2)
        decrypted, validsign = yield pgp.decrypt(encrypted_and_signed,
                                                 privkey,
                                                 verify=wrongkey)
        self.assertEqual(decrypted, data)
        self.assertFalse(validsign)

    @inlineCallbacks
    def test_sign_verify(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signed = pgp.sign(data, privkey, detach=False)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        validsign = pgp.verify(signed, pubkey)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_encrypt_sign_decrypt_verify(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        privkey = yield pgp.get_key(ADDRESS, private=True)

        yield pgp.put_raw_key(PRIVATE_KEY_2, ADDRESS_2)
        pubkey2 = yield pgp.get_key(ADDRESS_2, private=False)
        privkey2 = yield pgp.get_key(ADDRESS_2, private=True)

        data = 'data'
        encrypted_and_signed = yield pgp.encrypt(
            data, pubkey2, sign=privkey)
        res, validsign = yield pgp.decrypt(
            encrypted_and_signed, privkey2, verify=pubkey)
        self.assertEqual(data, res)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_sign_verify_detached_sig(self):
        data = 'data'
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        privkey = yield pgp.get_key(ADDRESS, private=True)
        signature = yield pgp.sign(data, privkey, detach=True)
        pubkey = yield pgp.get_key(ADDRESS, private=False)
        validsign = pgp.verify(data, pubkey, detached_sig=signature)
        self.assertTrue(validsign)

    @inlineCallbacks
    def test_self_repair_three_keys(self):
        refreshed_keep = datetime(2007, 1, 1)
        self._insert_key_docs([datetime(2005, 1, 1),
                               refreshed_keep,
                               datetime(2001, 1, 1)])
        delete_doc = self._mock_delete_doc()

        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        key = yield pgp.get_key(ADDRESS, private=False)
        self.assertEqual(key.refreshed_at, refreshed_keep)
        self.assertEqual(self.count, 2)
        self._soledad.delete_doc = delete_doc

    @inlineCallbacks
    def test_self_repair_no_keys(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)

        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc

        def my_get_from_index(*args):
            if (args[0] == TYPE_FINGERPRINT_PRIVATE_INDEX and
                    args[2] == KEY_FINGERPRINT):
                return succeed([])
            return get_from_index(*args)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))

        try:
            yield self.assertFailure(pgp.get_key(ADDRESS, private=False),
                                     KeyNotFound)
            # it should have deleted the index
            self.assertEqual(self._soledad.delete_doc.call_count, 1)
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc

    @inlineCallbacks
    def test_self_repair_put_keys(self):
        self._insert_key_docs([datetime(2005, 1, 1),
                               datetime(2007, 1, 1),
                               datetime(2001, 1, 1)])
        delete_doc = self._mock_delete_doc()

        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        yield pgp.put_raw_key(PUBLIC_KEY, ADDRESS)
        self._soledad.delete_doc = delete_doc
        self.assertEqual(self.count, 2)

    @inlineCallbacks
    def test_self_repair_five_active_docs(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc

        def my_get_from_index(*args):
            if (args[0] == TYPE_ADDRESS_PRIVATE_INDEX and
                    args[2] == ADDRESS):
                k1 = OpenPGPKey(ADDRESS, fingerprint="1",
                                last_audited_at=datetime(2005, 1, 1))
                k2 = OpenPGPKey(ADDRESS, fingerprint="2",
                                last_audited_at=datetime(2007, 1, 1))
                k3 = OpenPGPKey(ADDRESS, fingerprint="3",
                                last_audited_at=datetime(2007, 1, 1),
                                encr_used=True, sign_used=True)
                k4 = OpenPGPKey(ADDRESS, fingerprint="4",
                                last_audited_at=datetime(2007, 1, 1),
                                sign_used=True)
                k5 = OpenPGPKey(ADDRESS, fingerprint="5",
                                last_audited_at=datetime(2007, 1, 1),
                                encr_used=True)
                deferreds = []
                for k in (k1, k2, k3, k4, k5):
                    d = self._soledad.create_doc_from_json(
                        k.get_active_json())
                    deferreds.append(d)
                return gatherResults(deferreds)
            elif args[0] == TYPE_FINGERPRINT_PRIVATE_INDEX:
                fingerprint = args[2]
                self.assertEqual(fingerprint, "3")
                k = OpenPGPKey(ADDRESS, fingerprint="3")
                return succeed(
                    [self._soledad.create_doc_from_json(k.get_json())])
            return get_from_index(*args)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))

        try:
            yield pgp.get_key(ADDRESS, private=False)
            self.assertEqual(self._soledad.delete_doc.call_count, 4)
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc

    def _assert_key_not_found(self, pgp, address, private=False):
        d = pgp.get_key(address, private=private)
        return self.assertFailure(d, KeyNotFound)

    @inlineCallbacks
    def _insert_key_docs(self, refreshed_at):
        for date in refreshed_at:
            key = OpenPGPKey(ADDRESS, fingerprint=KEY_FINGERPRINT,
                             refreshed_at=date)
            yield self._soledad.create_doc_from_json(key.get_json())
        yield self._soledad.create_doc_from_json(key.get_active_json())

    def _mock_delete_doc(self):
        delete_doc = self._soledad.delete_doc
        self.count = 0

        def my_delete_doc(*args):
            self.count += 1
            return delete_doc(*args)
        self._soledad.delete_doc = my_delete_doc
        return delete_doc
