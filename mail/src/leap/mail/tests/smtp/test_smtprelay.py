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
    SMTPBadRcpt,
)
from mock import Mock


from leap.mail.smtp.smtprelay import (
    SMTPFactory,
    EncryptedMessage,
)
from leap.mail.tests.smtp import TestCaseWithKeyManager
from leap.common.keymanager import openpgp


# some regexps
IP_REGEX = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" + \
    "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
HOSTNAME_REGEX = "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*" + \
    "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"
IP_OR_HOST_REGEX = '(' + IP_REGEX + '|' + HOSTNAME_REGEX + ')'


class TestSmtpRelay(TestCaseWithKeyManager):

    EMAIL_DATA = ['HELO relay.leap.se',
                  'MAIL FROM: <user@leap.se>',
                  'RCPT TO: <leap@leap.se>',
                  'DATA',
                  'From: User <user@leap.se>',
                  'To: Leap <leap@leap.se>',
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
            'leap@leap.se', openpgp.OpenPGPKey, private=False)
        encrypted = openpgp.encrypt_asym(text, pubkey)
        self.assertNotEqual(text, encrypted, "failed encrypting text")
        privkey = self._km.get_key(
            'leap@leap.se', openpgp.OpenPGPKey, private=True)
        decrypted = openpgp.decrypt_asym(encrypted, privkey)
        self.assertEqual(text, decrypted, "failed decrypting text")

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
                             '\r\n'.join(SMTP_ANSWERS[0:i + 1]))
        proto.setTimeout(None)

    def test_message_encrypt(self):
        """
        Test if message gets encrypted to destination email.
        """
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        user = User('leap@leap.se', 'relay.leap.se', proto, 'leap@leap.se')
        m = EncryptedMessage(user, self._km, self._config)
        for line in self.EMAIL_DATA[4:12]:
            m.lineReceived(line)
        m.eomReceived()
        privkey = self._km.get_key(
            'leap@leap.se', openpgp.OpenPGPKey, private=True)
        decrypted = openpgp.decrypt_asym(m._message.get_payload(), privkey)
        self.assertEqual(
            '\r\n'.join(self.EMAIL_DATA[9:12]) + '\r\n',
            decrypted)

    def test_missing_key_rejects_address(self):
        """
        Test if server rejects to send unencrypted when 'encrypted_only' is
        True.
        """
        # remove key from key manager
        pubkey = self._km.get_key('leap@leap.se', openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(self._soledad)
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
            lines[-1])

    def test_missing_key_accepts_address(self):
        """
        Test if server accepts to send unencrypted when 'encrypted_only' is
        False.
        """
        # remove key from key manager
        pubkey = self._km.get_key('leap@leap.se', openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(self._soledad)
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
        # ensure the address was rejected
        lines = transport.value().rstrip().split('\n')
        self.assertEqual(
            '250 Recipient address accepted',
            lines[-1])

    def test_malformed_address_rejects(self):
        """
        Test if server rejects to send to malformed addresses.
        """
        # mock the key fetching
        self._km.fetch_keys_from_server = Mock(return_value=[])
        # prepare the SMTP factory
        for malformed in ['leap@']:
            proto = SMTPFactory(
                self._km, self._config).buildProtocol(('127.0.0.1', 0))
            transport = proto_helpers.StringTransport()
            proto.makeConnection(transport)
            proto.lineReceived(self.EMAIL_DATA[0] + '\r\n')
            proto.lineReceived(self.EMAIL_DATA[1] + '\r\n')
            proto.lineReceived('RCPT TO: <%s>%s' % (malformed, '\r\n'))
            # ensure the address was rejected
            lines = transport.value().rstrip().split('\n')
            self.assertEqual(
                '550 Cannot receive for specified address',
                lines[-1])

    def test_prepare_header_adds_from(self):
        """
        Test if message headers are OK.
        """
        proto = SMTPFactory(
            self._km, self._config).buildProtocol(('127.0.0.1', 0))
        user = User('leap@leap.se', 'relay.leap.se', proto, 'leap@leap.se')
        m = EncryptedMessage(user, self._km, self._config)
        for line in self.EMAIL_DATA[4:12]:
            m.lineReceived(line)
        m.eomReceived()
        self.assertEqual('<leap@leap.se>', m._message['From'])
