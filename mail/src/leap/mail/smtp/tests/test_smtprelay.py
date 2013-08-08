# -*- coding: utf-8 -*-
# test_smtprelay.py
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
SMTP relay tests.
"""


import re


from datetime import datetime
from twisted.test import proto_helpers
from twisted.mail.smtp import (
    User,
    Address,
    SMTPBadRcpt,
)
from mock import Mock


from leap.mail.smtp.smtprelay import (
    SMTPFactory,
    EncryptedMessage,
)
from leap.mail.smtp.tests import (
    TestCaseWithKeyManager,
    ADDRESS,
    ADDRESS_2,
)
from leap.keymanager import openpgp


# some regexps
IP_REGEX = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" + \
    "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
HOSTNAME_REGEX = "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*" + \
    "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"
IP_OR_HOST_REGEX = '(' + IP_REGEX + '|' + HOSTNAME_REGEX + ')'


class TestSmtpRelay(TestCaseWithKeyManager):

    EMAIL_DATA = ['HELO relay.leap.se',
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

    def assertMatch(self, string, pattern, msg=None):
        if not re.match(pattern, string):
            msg = self._formatMessage(msg, '"%s" does not match pattern "%s".'
                                           % (string, pattern))
            raise self.failureException(msg)

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

    def test_relay_accepts_valid_email(self):
        """
        Test if SMTP server responds correctly for valid interaction.
        """

        SMTP_ANSWERS = ['220 ' + IP_OR_HOST_REGEX +
                        ' NO UCE NO UBE NO RELAY PROBES',
                        '250 ' + IP_OR_HOST_REGEX + ' Hello ' +
                        IP_OR_HOST_REGEX + ', nice to meet you',
                        '250 Sender address accepted',
                        '250 Recipient address accepted',
                        '354 Continue']
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        for i, line in enumerate(self.EMAIL_DATA):
            proto.lineReceived(line + '\r\n')
            self.assertMatch(transport.value(),
                             '\r\n'.join(SMTP_ANSWERS[0:i + 1]),
                             'Did not get expected answer from relay.')
        proto.setTimeout(None)

    def test_message_encrypt(self):
        """
        Test if message gets encrypted to destination email.
        """
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        fromAddr = Address(ADDRESS_2)
        dest = User(ADDRESS, 'relay.leap.se', proto, ADDRESS)
        m = EncryptedMessage(fromAddr, dest, self._km, self._config)
        for line in self.EMAIL_DATA[4:12]:
            m.lineReceived(line)
        m.eomReceived()
        privkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=True)
        decrypted = self._km.decrypt(m._message.get_payload(), privkey)
        self.assertEqual(
            '\r\n'.join(self.EMAIL_DATA[9:12]) + '\r\n',
            decrypted,
            'Decrypted text differs from plaintext.')

    def test_message_encrypt_sign(self):
        """
        Test if message gets encrypted to destination email and signed with
        sender key.
        """
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        user = User(ADDRESS, 'relay.leap.se', proto, ADDRESS)
        fromAddr = Address(ADDRESS_2)
        m = EncryptedMessage(fromAddr, user, self._km, self._config)
        for line in self.EMAIL_DATA[4:12]:
            m.lineReceived(line)
        # trigger encryption and signing
        m.eomReceived()
        # decrypt and verify
        privkey = self._km.get_key(
            ADDRESS, openpgp.OpenPGPKey, private=True)
        pubkey = self._km.get_key(ADDRESS_2, openpgp.OpenPGPKey)
        decrypted = self._km.decrypt(
            m._message.get_payload(), privkey, verify=pubkey)
        self.assertEqual(
            '\r\n'.join(self.EMAIL_DATA[9:12]) + '\r\n',
            decrypted,
            'Decrypted text differs from plaintext.')

    def test_message_sign(self):
        """
        Test if message is signed with sender key.
        """
        # mock the key fetching
        self._km.fetch_keys_from_server = Mock(return_value=[])
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        user = User('ihavenopubkey@nonleap.se', 'relay.leap.se', proto, ADDRESS)
        fromAddr = Address(ADDRESS_2)
        m = EncryptedMessage(fromAddr, user, self._km, self._config)
        for line in self.EMAIL_DATA[4:12]:
            m.lineReceived(line)
        # trigger signing
        m.eomReceived()
        # assert content of message
        self.assertTrue(
            m._message.get_payload().startswith(
                '-----BEGIN PGP SIGNED MESSAGE-----\n' +
                'Hash: SHA1\n\n' + 
                ('\r\n'.join(self.EMAIL_DATA[9:12]) + '\r\n' +
                '-----BEGIN PGP SIGNATURE-----\n')),
            'Message does not start with signature header.')
        self.assertTrue(
            m._message.get_payload().endswith(
                '-----END PGP SIGNATURE-----\n'),
            'Message does not end with signature footer.')
        # assert signature is valid
        pubkey = self._km.get_key(ADDRESS_2, openpgp.OpenPGPKey)
        self.assertTrue(
            self._km.verify(m._message.get_payload(), pubkey),
            'Signature could not be verified.')

    def test_missing_key_rejects_address(self):
        """
        Test if server rejects to send unencrypted when 'encrypted_only' is
        True.
        """
        # remove key from key manager
        pubkey = self._km.get_key(ADDRESS, openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.GPG_BINARY_PATH)
        pgp.delete_key(pubkey)
        # mock the key fetching
        self._km.fetch_keys_from_server = Mock(return_value=[])
        # prepare the SMTP factory
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        proto.lineReceived(self.EMAIL_DATA[0] + '\r\n')
        proto.lineReceived(self.EMAIL_DATA[1] + '\r\n')
        proto.lineReceived(self.EMAIL_DATA[2] + '\r\n')
        # ensure the address was rejected
        lines = transport.value().rstrip().split('\n')
        self.assertEqual(
            '550 Cannot receive for specified address',
            lines[-1],
            'Address should have been rejecetd with appropriate message.')

    def test_missing_key_accepts_address(self):
        """
        Test if server accepts to send unencrypted when 'encrypted_only' is
        False.
        """
        # remove key from key manager
        pubkey = self._km.get_key(ADDRESS, openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.GPG_BINARY_PATH)
        pgp.delete_key(pubkey)
        # mock the key fetching
        self._km.fetch_keys_from_server = Mock(return_value=[])
        # change the configuration
        self._config['encrypted_only'] = False
        # prepare the SMTP factory
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        proto.lineReceived(self.EMAIL_DATA[0] + '\r\n')
        proto.lineReceived(self.EMAIL_DATA[1] + '\r\n')
        proto.lineReceived(self.EMAIL_DATA[2] + '\r\n')
        # ensure the address was accepted
        lines = transport.value().rstrip().split('\n')
        self.assertEqual(
            '250 Recipient address accepted',
            lines[-1],
            'Address should have been accepted with appropriate message.')
