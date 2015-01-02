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
from twisted.internet.defer import fail
from twisted.mail.smtp import User

from mock import Mock

from leap.mail.smtp.gateway import SMTPFactory
from leap.mail.outgoing.service import OutgoingMail
from leap.mail.tests import (
    TestCaseWithKeyManager,
    ADDRESS,
    ADDRESS_2,
)
from leap.keymanager import openpgp, errors


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
        self.lines = [line for line in self.EMAIL_DATA[4:12]]
        self.lines.append('')  # add a trailing newline
        self.raw = '\r\n'.join(self.lines)
        self.expected_body = ('\r\n'.join(self.EMAIL_DATA[9:12]) +
                              "\r\n\r\n--\r\nI prefer encrypted email - "
                              "https://leap.se/key/anotheruser\r\n")
        self.fromAddr = ADDRESS_2

        def init_outgoing_and_proto(_):
            self.outgoing_mail = OutgoingMail(
                self.fromAddr, self._km, self._config['cert'],
                self._config['key'], self._config['host'],
                self._config['port'])
            self.proto = SMTPFactory(
                u'anotheruser@leap.se',
                self._km,
                self._config['encrypted_only'],
                self.outgoing_mail).buildProtocol(('127.0.0.1', 0))
            self.dest = User(ADDRESS, 'gateway.leap.se', self.proto, ADDRESS)

        d = TestCaseWithKeyManager.setUp(self)
        d.addCallback(init_outgoing_and_proto)
        return d

    def test_message_encrypt(self):
        """
        Test if message gets encrypted to destination email.
        """
        def check_decryption(res):
            decrypted, _ = res
            self.assertEqual(
                '\n' + self.expected_body,
                decrypted,
                'Decrypted text differs from plaintext.')

        d = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, self.dest)
        d.addCallback(self._assert_encrypted)
        d.addCallback(lambda message: self._km.decrypt(
            message.get_payload(1).get_payload(), ADDRESS, openpgp.OpenPGPKey))
        d.addCallback(check_decryption)
        return d

    def test_message_encrypt_sign(self):
        """
        Test if message gets encrypted to destination email and signed with
        sender key.
        '"""
        def check_decryption_and_verify(res):
            decrypted, signkey = res
            self.assertEqual(
                '\n' + self.expected_body,
                decrypted,
                'Decrypted text differs from plaintext.')
            self.assertTrue(ADDRESS_2 in signkey.address,
                            "Verification failed")

        d = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, self.dest)
        d.addCallback(self._assert_encrypted)
        d.addCallback(lambda message: self._km.decrypt(
            message.get_payload(1).get_payload(), ADDRESS, openpgp.OpenPGPKey,
            verify=ADDRESS_2))
        d.addCallback(check_decryption_and_verify)
        return d

    def test_message_sign(self):
        """
        Test if message is signed with sender key.
        """
        # mock the key fetching
        self._km._fetch_keys_from_server = Mock(
            return_value=fail(errors.KeyNotFound()))
        recipient = User('ihavenopubkey@nonleap.se',
                         'gateway.leap.se', self.proto, ADDRESS)
        self.outgoing_mail = OutgoingMail(
            self.fromAddr, self._km, self._config['cert'], self._config['key'],
            self._config['host'], self._config['port'])

        def check_signed(res):
            message, _ = res
            self.assertTrue('Content-Type' in message)
            self.assertEqual('multipart/signed', message.get_content_type())
            self.assertEqual('application/pgp-signature',
                             message.get_param('protocol'))
            self.assertEqual('pgp-sha512', message.get_param('micalg'))
            # assert content of message
            self.assertEqual(self.expected_body,
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
            return message

        def verify(message):
            # replace EOL before verifying (according to rfc3156)
            signed_text = re.sub('\r?\n', '\r\n',
                                 message.get_payload(0).as_string())

            def assert_verify(key):
                self.assertTrue(ADDRESS_2 in key.address,
                                 'Signature could not be verified.')

            d = self._km.verify(
                signed_text, ADDRESS_2, openpgp.OpenPGPKey,
                detached_sig=message.get_payload(1).get_payload())
            d.addCallback(assert_verify)
            return d

        d = self.outgoing_mail._maybe_encrypt_and_sign(self.raw, recipient)
        d.addCallback(check_signed)
        d.addCallback(verify)
        return d

    def _assert_encrypted(self, res):
        message, _ = res
        self.assertTrue('Content-Type' in message)
        self.assertEqual('multipart/encrypted', message.get_content_type())
        self.assertEqual('application/pgp-encrypted',
                         message.get_param('protocol'))
        self.assertEqual(2, len(message.get_payload()))
        self.assertEqual('application/pgp-encrypted',
                         message.get_payload(0).get_content_type())
        self.assertEqual('application/octet-stream',
                         message.get_payload(1).get_content_type())
        return message
