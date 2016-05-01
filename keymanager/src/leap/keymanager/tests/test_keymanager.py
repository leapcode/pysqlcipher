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

from os import path
import json
import urllib
from datetime import datetime
import tempfile
import pkg_resources
from leap.common import ca_bundle
from mock import Mock, MagicMock, patch
from twisted.internet import defer
from twisted.trial import unittest
from twisted.web._responses import NOT_FOUND

from leap.keymanager import client

from leap.keymanager import errors
from leap.keymanager.keys import (
    OpenPGPKey,
    is_address,
    build_key_from_dict,
)
from leap.keymanager.validation import ValidationLevels
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


NICKSERVER_URI = "http://leap.se/"
REMOTE_KEY_URL = "http://site.domain/key"
INVALID_MAIL_ADDRESS = "notexistingemail@example.org"


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
            'uids': [ADDRESS],
            'fingerprint': KEY_FINGERPRINT,
            'key_data': PUBLIC_KEY,
            'private': False,
            'length': 4096,
            'expiry_date': 0,
            'refreshed_at': 1311239602,
        }
        adict = {
            'address': ADDRESS,
            'private': False,
            'last_audited_at': 0,
            'validation': str(ValidationLevels.Weak_Chain),
            'encr_used': False,
            'sign_used': True,
        }
        key = build_key_from_dict(OpenPGPKey, kdict, adict)
        self.assertEqual(
            kdict['uids'], key.uids,
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
            adict['address'], key.address,
            'Wrong data in key.')
        self.assertEqual(
            ValidationLevels.get(adict['validation']), key.validation,
            'Wrong data in key.')
        self.assertEqual(
            adict['encr_used'], key.encr_used,
            'Wrong data in key.')
        self.assertEqual(
            adict['sign_used'], key.sign_used,
            'Wrong data in key.')


class KeyManagerKeyManagementTestCase(KeyManagerWithSoledadTestCase):

    @defer.inlineCallbacks
    def test_get_all_keys_in_db(self):
        km = self._key_manager()
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        # get public keys
        keys = yield km.get_all_keys(False)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertTrue(ADDRESS in keys[0].uids)
        self.assertFalse(keys[0].private)
        # get private keys
        keys = yield km.get_all_keys(True)
        self.assertEqual(len(keys), 1, 'Wrong number of keys')
        self.assertTrue(ADDRESS in keys[0].uids)
        self.assertTrue(keys[0].private)

    @defer.inlineCallbacks
    def test_get_public_key(self):
        km = self._key_manager()
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        # get the key
        key = yield km.get_key(ADDRESS, private=False, fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertTrue(ADDRESS in key.uids)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertFalse(key.private)

    @defer.inlineCallbacks
    def test_get_public_key_with_binary_private_key(self):
        km = self._key_manager()
        yield km._openpgp.put_raw_key(self.get_private_binary_key(), ADDRESS)
        # get the key
        key = yield km.get_key(ADDRESS, private=False, fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertTrue(ADDRESS in key.uids)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertFalse(key.private)

    @defer.inlineCallbacks
    def test_get_private_key(self):
        km = self._key_manager()
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        # get the key
        key = yield km.get_key(ADDRESS, private=True, fetch_remote=False)
        self.assertTrue(key is not None)
        self.assertTrue(ADDRESS in key.uids)
        self.assertEqual(
            key.fingerprint.lower(), KEY_FINGERPRINT.lower())
        self.assertTrue(key.private)

    def test_send_key_raises_key_not_found(self):
        km = self._key_manager()
        d = km.send_key()
        return self.assertFailure(d, errors.KeyNotFound)

    @defer.inlineCallbacks
    def test_send_key(self):
        """
        Test that request is well formed when sending keys to server.
        """
        token = "mytoken"
        km = self._key_manager(token=token)
        yield km._openpgp.put_raw_key(PUBLIC_KEY, ADDRESS)
        km._async_client_pinned.request = Mock(return_value=defer.succeed(''))
        # the following data will be used on the send
        km.ca_cert_path = 'capath'
        km.session_id = 'sessionid'
        km.uid = 'myuid'
        km.api_uri = 'apiuri'
        km.api_version = 'apiver'
        yield km.send_key()
        # setup expected args
        pubkey = yield km.get_key(km._address)
        data = urllib.urlencode({
            km.PUBKEY_KEY: pubkey.key_data,
        })
        headers = {'Authorization': [str('Token token=%s' % token)]}
        headers['Content-Type'] = ['application/x-www-form-urlencoded']
        url = '%s/%s/users/%s.json' % ('apiuri', 'apiver', 'myuid')
        km._async_client_pinned.request.assert_called_once_with(
            str(url), 'PUT', body=str(data),
            headers=headers
        )

    def test_fetch_keys_from_server(self):
        """
        Test that the request is well formed when fetching keys from server.
        """
        km = self._key_manager(url=NICKSERVER_URI)
        expected_url = NICKSERVER_URI + '?address=' + ADDRESS_2

        def verify_the_call(_):
            used_kwargs = km._async_client_pinned.request.call_args[1]
            km._async_client_pinned.request.assert_called_once_with(expected_url, 'GET', **used_kwargs)

        d = self._fetch_key(km, ADDRESS_2, PUBLIC_KEY_2)
        d.addCallback(verify_the_call)
        return d

    def test_key_not_found_is_raised_if_key_search_responds_404(self):
        """
        Test if key search request comes back with a 404 response then KeyNotFound is raised, with corresponding error message.
        """
        km = self._key_manager(url=NICKSERVER_URI)
        client.readBody = Mock(return_value=defer.succeed(None))
        km._async_client_pinned.request = Mock(return_value=defer.succeed(None))
        url = NICKSERVER_URI + '?address=' + INVALID_MAIL_ADDRESS

        d = km._fetch_and_handle_404_from_nicknym(url, INVALID_MAIL_ADDRESS)

        def check_key_not_found_is_raised_if_404(_):
            used_kwargs = km._async_client_pinned.request.call_args[1]
            check_404_callback = used_kwargs['callback']
            fake_response = Mock()
            fake_response.code = NOT_FOUND
            with self.assertRaisesRegexp(KeyNotFound, '404: %s key not found.' % INVALID_MAIL_ADDRESS):
                check_404_callback(fake_response)

        d.addCallback(check_key_not_found_is_raised_if_404)
        return d

    def test_non_existing_key_from_nicknym_is_relayed(self):
        """
        Test if key search requests throws KeyNotFound, the same error is raised.
        """
        km = self._key_manager(url=NICKSERVER_URI)
        key_not_found_exception = KeyNotFound('some message')
        km._async_client_pinned.request = Mock(side_effect=key_not_found_exception)

        def assert_key_not_found_raised(error):
            self.assertEqual(error.value, key_not_found_exception)

        d = km._get_key_from_nicknym(INVALID_MAIL_ADDRESS)
        d.addErrback(assert_key_not_found_raised)

    @defer.inlineCallbacks
    def test_get_key_fetches_from_server(self):
        """
        Test that getting a key successfuly fetches from server.
        """
        km = self._key_manager(url=NICKSERVER_URI)

        key = yield self._fetch_key(km, ADDRESS, PUBLIC_KEY)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS in key.uids)
        self.assertEqual(key.validation, ValidationLevels.Provider_Trust)

    @defer.inlineCallbacks
    def test_get_key_fetches_other_domain(self):
        """
        Test that getting a key successfuly fetches from server.
        """
        km = self._key_manager(url=NICKSERVER_URI)

        key = yield self._fetch_key(km, ADDRESS_OTHER, PUBLIC_KEY_OTHER)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS_OTHER in key.uids)
        self.assertEqual(key.validation, ValidationLevels.Weak_Chain)

    def _fetch_key(self, km, address, key):
        """
        :returns: a Deferred that will fire with the OpenPGPKey
        """
        data = json.dumps({'address': address, 'openpgp': key})

        client.readBody = Mock(return_value=defer.succeed(data))

        # mock the fetcher so it returns the key for ADDRESS_2
        km._async_client_pinned.request = Mock(return_value=defer.succeed(None))
        km.ca_cert_path = 'cacertpath'
        # try to key get without fetching from server
        d_fail = km.get_key(address, fetch_remote=False)
        d = self.assertFailure(d_fail, errors.KeyNotFound)
        # try to get key fetching from server.
        d.addCallback(lambda _: km.get_key(address))
        return d

    @defer.inlineCallbacks
    def test_put_key_ascii(self):
        """
        Test that putting ascii key works
        """
        km = self._key_manager(url=NICKSERVER_URI)

        yield km.put_raw_key(PUBLIC_KEY, ADDRESS)
        key = yield km.get_key(ADDRESS)
        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS in key.uids)

    @defer.inlineCallbacks
    def test_put_key_binary(self):
        """
        Test that putting binary key works
        """
        km = self._key_manager(url=NICKSERVER_URI)

        yield km.put_raw_key(self.get_public_binary_key(), ADDRESS)
        key = yield km.get_key(ADDRESS)

        self.assertIsInstance(key, OpenPGPKey)
        self.assertTrue(ADDRESS in key.uids)

    @defer.inlineCallbacks
    def test_fetch_uri_ascii_key(self):
        """
        Test that fetch key downloads the ascii key and gets included in
        the local storage
        """
        km = self._key_manager()

        km._async_client.request = Mock(return_value=defer.succeed(PUBLIC_KEY))

        yield km.fetch_key(ADDRESS, "http://site.domain/key")
        key = yield km.get_key(ADDRESS)
        self.assertEqual(KEY_FINGERPRINT, key.fingerprint)

    @defer.inlineCallbacks
    def test_fetch_uri_binary_key(self):
        """
        Test that fetch key downloads the binary key and gets included in
        the local storage
        """
        km = self._key_manager()

        km._async_client.request = Mock(
            return_value=defer.succeed(self.get_public_binary_key()))

        yield km.fetch_key(ADDRESS, "http://site.domain/key")
        key = yield km.get_key(ADDRESS)
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
        d = km.fetch_key(ADDRESS, "http://site.domain/key")
        return self.assertFailure(d, errors.KeyNotFound)

    def test_fetch_uri_address_differ(self):
        """
        Test that fetch key raises KeyAttributesDiffer if the address
        don't match
        """
        km = self._key_manager()

        km._async_client.request = Mock(return_value=defer.succeed(PUBLIC_KEY))
        d = km.fetch_key(ADDRESS_2, "http://site.domain/key")
        return self.assertFailure(d, errors.KeyAddressMismatch)

    def _mock_get_response(self, km, body):
        km._async_client.request = MagicMock(return_value=defer.succeed(body))

        return km._async_client.request

    @defer.inlineCallbacks
    def test_fetch_key_uses_ca_bundle_if_none_specified(self):
        ca_cert_path = None
        km = self._key_manager(ca_cert_path=ca_cert_path)
        get_mock = self._mock_get_response(km, PUBLIC_KEY_OTHER)

        yield km.fetch_key(ADDRESS_OTHER, REMOTE_KEY_URL)

        get_mock.assert_called_once_with(REMOTE_KEY_URL, 'GET')

    @defer.inlineCallbacks
    def test_fetch_key_uses_ca_bundle_if_empty_string_specified(self):
        ca_cert_path = ''
        km = self._key_manager(ca_cert_path=ca_cert_path)
        get_mock = self._mock_get_response(km, PUBLIC_KEY_OTHER)

        yield km.fetch_key(ADDRESS_OTHER, REMOTE_KEY_URL)

        get_mock.assert_called_once_with(REMOTE_KEY_URL, 'GET')

    @defer.inlineCallbacks
    def test_fetch_key_use_default_ca_bundle_if_set_as_ca_cert_path(self):
        ca_cert_path = ca_bundle.where()
        km = self._key_manager(ca_cert_path=ca_cert_path)
        get_mock = self._mock_get_response(km, PUBLIC_KEY_OTHER)

        yield km.fetch_key(ADDRESS_OTHER, REMOTE_KEY_URL)

        get_mock.assert_called_once_with(REMOTE_KEY_URL, 'GET')

    @defer.inlineCallbacks
    def test_fetch_uses_combined_ca_bundle_otherwise(self):
        with tempfile.NamedTemporaryFile() as tmp_input, \
                tempfile.NamedTemporaryFile(delete=False) as tmp_output:
            ca_content = pkg_resources.resource_string('leap.common.testing',
                                                       'cacert.pem')
            ca_cert_path = tmp_input.name
            self._dump_to_file(ca_cert_path, ca_content)

            with patch('leap.keymanager.tempfile.NamedTemporaryFile') as mock:
                mock.return_value = tmp_output
                km = self._key_manager(ca_cert_path=ca_cert_path)
                get_mock = self._mock_get_response(km, PUBLIC_KEY_OTHER)

                yield km.fetch_key(ADDRESS_OTHER, REMOTE_KEY_URL)

                # assert that combined bundle file is passed to get call
                get_mock.assert_called_once_with(REMOTE_KEY_URL, 'GET')

                # assert that files got appended
                expected = self._slurp_file(ca_bundle.where()) + ca_content
                self.assertEqual(expected, self._slurp_file(tmp_output.name))

            del km  # force km out of scope
            self.assertFalse(path.exists(tmp_output.name))

    def _dump_to_file(self, filename, content):
            with open(filename, 'w') as out:
                out.write(content)

    def _slurp_file(self, filename):
        with open(filename) as f:
            content = f.read()
        return content

    @defer.inlineCallbacks
    def test_decrypt_updates_sign_used_for_signer(self):
        # given
        km = self._key_manager()
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        yield km._openpgp.put_raw_key(PRIVATE_KEY_2, ADDRESS_2)
        encdata = yield km.encrypt('data', ADDRESS, sign=ADDRESS_2,
                                   fetch_remote=False)
        yield km.decrypt(
            encdata, ADDRESS, verify=ADDRESS_2, fetch_remote=False)

        # when
        key = yield km.get_key(ADDRESS_2, fetch_remote=False)

        # then
        self.assertEqual(True, key.sign_used)

    @defer.inlineCallbacks
    def test_decrypt_does_not_update_sign_used_for_recipient(self):
        # given
        km = self._key_manager()
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        yield km._openpgp.put_raw_key(PRIVATE_KEY_2, ADDRESS_2)
        encdata = yield km.encrypt('data', ADDRESS, sign=ADDRESS_2,
                                   fetch_remote=False)
        yield km.decrypt(
            encdata, ADDRESS, verify=ADDRESS_2, fetch_remote=False)

        # when
        key = yield km.get_key(
            ADDRESS, private=False, fetch_remote=False)

        # then
        self.assertEqual(False, key.sign_used)


class KeyManagerCryptoTestCase(KeyManagerWithSoledadTestCase):

    RAW_DATA = 'data'

    @defer.inlineCallbacks
    def test_keymanager_openpgp_encrypt_decrypt(self):
        km = self._key_manager()
        # put raw private key
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        yield km._openpgp.put_raw_key(PRIVATE_KEY_2, ADDRESS_2)
        # encrypt
        encdata = yield km.encrypt(self.RAW_DATA, ADDRESS, sign=ADDRESS_2,
                                   fetch_remote=False)
        self.assertNotEqual(self.RAW_DATA, encdata)
        # decrypt
        rawdata, signingkey = yield km.decrypt(
            encdata, ADDRESS, verify=ADDRESS_2, fetch_remote=False)
        self.assertEqual(self.RAW_DATA, rawdata)
        key = yield km.get_key(ADDRESS_2, private=False, fetch_remote=False)
        self.assertEqual(signingkey.fingerprint, key.fingerprint)

    @defer.inlineCallbacks
    def test_keymanager_openpgp_encrypt_decrypt_wrong_sign(self):
        km = self._key_manager()
        # put raw keys
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        yield km._openpgp.put_raw_key(PRIVATE_KEY_2, ADDRESS_2)
        # encrypt
        encdata = yield km.encrypt(self.RAW_DATA, ADDRESS, sign=ADDRESS_2,
                                   fetch_remote=False)
        self.assertNotEqual(self.RAW_DATA, encdata)
        # verify
        rawdata, signingkey = yield km.decrypt(
            encdata, ADDRESS, verify=ADDRESS, fetch_remote=False)
        self.assertEqual(self.RAW_DATA, rawdata)
        self.assertTrue(isinstance(signingkey, errors.InvalidSignature))

    @defer.inlineCallbacks
    def test_keymanager_openpgp_sign_verify(self):
        km = self._key_manager()
        # put raw private keys
        yield km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        signdata = yield km.sign(self.RAW_DATA, ADDRESS, detach=False)
        self.assertNotEqual(self.RAW_DATA, signdata)
        # verify
        signingkey = yield km.verify(signdata, ADDRESS, fetch_remote=False)
        key = yield km.get_key(ADDRESS, private=False, fetch_remote=False)
        self.assertEqual(signingkey.fingerprint, key.fingerprint)

    def test_keymanager_encrypt_key_not_found(self):
        km = self._key_manager()
        d = km._openpgp.put_raw_key(PRIVATE_KEY, ADDRESS)
        d.addCallback(
            lambda _: km.encrypt(self.RAW_DATA, ADDRESS_2, sign=ADDRESS,
                                 fetch_remote=False))
        return self.assertFailure(d, errors.KeyNotFound)

if __name__ == "__main__":
    import unittest
    unittest.main()

# key 0F91B402: someone@somedomain.org
# 9420 EC7B 6DCB 867F 5592  E6D1 7504 C974 0F91 B402
ADDRESS_OTHER = "someone@somedomain.org"
PUBLIC_KEY_OTHER = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFUZFLwBCADRzTstykRAV3aWysLAV4O3DXdpXhV3Cww8Pfc6m1bVxAT2ifcL
kLWEaIkOB48SYIHbYzqOi1/h5abJf+5n4uhaIks+FsjsXYo1XOiYpVCNf7+xLnUM
jkmglKT5sASr61QDcFMqWfGTJ8iUTNVCJZ2k14QJ4Vss/ntnV9uB7Ef7wU7RZvxr
wINH/0LfKPsGE9l2qNpKUAAmg2bHn9YdsHj1sqlW7eZpwvefYrQej4KBaL2oq3vt
QQOdXGFqWYMe3cX+bQ1DAMG3ttTF6EGkY97BK7A18I/RJiLujWCEAkMzFr5SK9KU
AOMj6MpjfTOE+GfUKsu7/gGt42eMBFsIOvsZABEBAAG0IFNvbWVvbmUgPHNvbWVv
bmVAc29tZWRvbWFpbi5vcmc+iQE4BBMBAgAiBQJVGRS8AhsDBgsJCAcDAgYVCAIJ
CgsEFgIDAQIeAQIXgAAKCRB1BMl0D5G0AlFsCAC33LhxBRwO64T6DgTb4/39aLpi
9T3yAmXBAHC7Q+4f37IBX5fJBRKu4Lvfp6KherOl/I/Jj34yv8pm0j+kXeWktfxZ
cW+mv2vjBHQVopiUSyMVh7caFSq9sKm+oQdo6oIl9DHSARegbkCn2+0b4VxgJpyj
TZBMyUMD2AayivQU4QHOM3KCozhLNNDbpKy7LH0MSAUDmRaJsPk1zK15lQocK/7R
Z5yF4rdrdzDWrVucZJc09yntSqTGECue3W2GBCaBlb/O1c9xei4MTb4nSHS5Gp/7
hcjrvIrgPpehndk8ZRREN/Y8uk1W5fbWzx+5z8g31RCGWBQw4NAnG10NZ3oEuQEN
BFUZFLwBCADocYZmLu1iXIE6gKqniR6Z8UDC5XnqgK+BEJwi1abe9zWhjgKeW9Vv
u1i194wuCUiNkP/bMvwMBZLTslDzqxl32ETk9FvB3kWy80S8MDjQJ15IN4I622fq
MEWwtQ0WrRay9VV6M8H2mIf71/1d5T9ysWK4XRyv+N7eRhfg7T2uhrpNyKdCZzjq
2wlgpVkMY7gtxTqJseM+qS5UNiReGxtoOXFLzzmagFgbqK88eMeZJZt8yKf81xhP
SWLTxaVaeBEAlajvEkxZJrrDQuc+maTwtMxmNUe815wJnpcRF8VD91GUpSLAN6EC
1QuJUl6Lc2o2tcHeo6CGsDZ96o0J8pFhABEBAAGJAR8EGAECAAkFAlUZFLwCGwwA
CgkQdQTJdA+RtAKcdwgApzHPhwwaZ9TBjgOytke/hPE0ht/EJ5nRiIda2PucoPh6
DwnaI8nvmGXUfC4qFy6LM8/fJHof1BqLnMbx8MCLurnm5z30q8RhLE3YWM11zuMy
6wkHGmi/6S1G4okC+Uu8AA4K//HBo8bLcqGVWRnFAmCqy6VMAofsQvmM7vHbRj56
U919Bki/7I6kcxPEzO73Umh3o82VP/Hz3JMigRNBRfG3jPrX04RLJj3Ib5lhQIDw
XrO8VHz9foOpY+rJnWj+6QAozxorzZYShu6H0GR1nIuqWMwli1nrx6BeIJAVz5cg
QzEd9yAN+81fkIBaa6Y8LCBxV03JCc2J4eCUKXd1gg==
=gDzy
-----END PGP PUBLIC KEY BLOCK-----
"""
