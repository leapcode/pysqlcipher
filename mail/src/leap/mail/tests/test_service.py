# -*- coding: utf-8 -*-
# test_gateway.py
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
SMTP gateway tests.
"""

import re
from datetime import datetime
from twisted.mail.smtp import User, Address

from mock import Mock

from leap.mail.smtp.gateway import SMTPFactory
from leap.mail.service import OutgoingMail
from leap.mail.tests import (
    TestCaseWithKeyManager,
    ADDRESS,
    ADDRESS_2,
)
from leap.keymanager import openpgp


class TestOutgoingMail(TestCaseWithKeyManager):
    EMAIL_DATA = ['HELO gateway.leap.se',
                  'MAIL FROM: <%s>' % ADDRESS_2,
                  'RCPT TO: <%s>' % ADDRESS,
                  'DATA',
                  'From: User <%s>' % ADDRESS_2,
                  'To: Leap <%s>' % ADDRESS,
                  'Date: ' + datetime.now().strftime('%c'),
                  'Subject: test message',
                  '',
                  'This is a secret message.',
                  'Yours,',
                  'A.',
                  '',
                  '.',
                  'QUIT']

    def setUp(self):
        TestCaseWithKeyManager.setUp(self)
        self.lines = [line for line in self.EMAIL_DATA[4:12]]
        self.lines.append('')  # add a trailing newline
        self.raw = '\r\n'.join(self.lines)
        self.fromAddr = ADDRESS_2
        self.outgoing_mail = OutgoingMail(self.fromAddr, self._km, self._config['cert'], self._config['key'],
                                        self._config['host'], self._config['port'])
        self.proto = SMTPFactory(
            u'anotheruser@leap.se',
            self._km,
            self._config['encrypted_only'],
            self.outgoing_mail).buildProtocol(('127.0.0.1', 0))
        self.dest = User(ADDRESS, 'gateway.leap.se', self.proto, ADDRESS)

    def test_openpgp_encrypt_decrypt(self):
        "Test if openpgp can encrypt and decrypt."
        text = "simple raw text"
        pubkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=False)
        encrypted = self._km.encrypt(text, pubkey)
        self.assertNotEqual(
            text, encrypted, "Ciphertext is equal to plaintext.")
        privkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=True)
        decrypted = self._km.decrypt(encrypted, privkey)
        self.assertEqual(text, decrypted,
                         "Decrypted text differs from plaintext.")

    def test_message_encrypt(self):
        """
        Test if message gets encrypted to destination email.
        """

        message, _ = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, self.dest)

        # assert structure of encrypted message
        self.assertTrue('Content-Type' in message)
        self.assertEqual('multipart/encrypted', message.get_content_type())
        self.assertEqual('application/pgp-encrypted',
                         message.get_param('protocol'))
        self.assertEqual(2, len(message.get_payload()))
        self.assertEqual('application/pgp-encrypted',
                         message.get_payload(0).get_content_type())
        self.assertEqual('application/octet-stream',
                         message.get_payload(1).get_content_type())
        privkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=True)
        decrypted = self._km.decrypt(
            message.get_payload(1).get_payload(), privkey)

        expected = '\n' + '\r\n'.join(
            self.EMAIL_DATA[9:12]) + '\r\n\r\n--\r\n' + 'I prefer encrypted email - https://leap.se/key/anotheruser\r\n'
        self.assertEqual(
            expected,
            decrypted,
            'Decrypted text differs from plaintext.')

    def test_message_encrypt_sign(self):
        """
        Test if message gets encrypted to destination email and signed with
        sender key.
        """
        message, _ = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, self.dest)

        # assert structure of encrypted message
        self.assertTrue('Content-Type' in message)
        self.assertEqual('multipart/encrypted', message.get_content_type())
        self.assertEqual('application/pgp-encrypted',
                         message.get_param('protocol'))
        self.assertEqual(2, len(message.get_payload()))
        self.assertEqual('application/pgp-encrypted',
                         message.get_payload(0).get_content_type())
        self.assertEqual('application/octet-stream',
                         message.get_payload(1).get_content_type())
        # decrypt and verify
        privkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=True)
        pubkey = self._km.get_key(ADDRESS_2, openpgp.OpenPGPKey)
        decrypted = self._km.decrypt(
            message.get_payload(1).get_payload(), privkey, verify=pubkey)
        self.assertEqual(
            '\n' + '\r\n'.join(self.EMAIL_DATA[9:12]) + '\r\n\r\n--\r\n' +
            'I prefer encrypted email - https://leap.se/key/anotheruser\r\n',
            decrypted,
            'Decrypted text differs from plaintext.')

    def test_message_sign(self):
        """
        Test if message is signed with sender key.
        """
        # mock the key fetching
        self._km.fetch_keys_from_server = Mock(return_value=[])
        recipient = User('ihavenopubkey@nonleap.se',
                    'gateway.leap.se', self.proto, ADDRESS)
        self.outgoing_mail = OutgoingMail(self.fromAddr, self._km, self._config['cert'], self._config['key'],
                                        self._config['host'], self._config['port'])

        message, _ = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, recipient)

        # assert structure of signed message
        self.assertTrue('Content-Type' in message)
        self.assertEqual('multipart/signed', message.get_content_type())
        self.assertEqual('application/pgp-signature',
                         message.get_param('protocol'))
        self.assertEqual('pgp-sha512', message.get_param('micalg'))
        # assert content of message
        self.assertEqual(
            '\r\n'.join(self.EMAIL_DATA[9:13]) + '\r\n--\r\n' +
            'I prefer encrypted email - https://leap.se/key/anotheruser\r\n',
            message.get_payload(0).get_payload(decode=True))
        # assert content of signature
        self.assertTrue(
            message.get_payload(1).get_payload().startswith(
                '-----BEGIN PGP SIGNATURE-----\n'),
            'Message does not start with signature header.')
        self.assertTrue(
            message.get_payload(1).get_payload().endswith(
                '-----END PGP SIGNATURE-----\n'),
            'Message does not end with signature footer.')
        # assert signature is valid
        pubkey = self._km.get_key(ADDRESS_2, openpgp.OpenPGPKey)
        # replace EOL before verifying (according to rfc3156)
        signed_text = re.sub('\r?\n', '\r\n',
                             message.get_payload(0).as_string())
        self.assertTrue(
            self._km.verify(signed_text,
                            pubkey,
                            detached_sig=message.get_payload(1).get_payload()),
            'Signature could not be verified.')
