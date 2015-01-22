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

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, fail, succeed, Deferred
from twisted.test import proto_helpers

from mock import Mock
from leap.mail.smtp.gateway import (
    SMTPFactory
)
from leap.mail.tests import (
    TestCaseWithKeyManager,
    ADDRESS,
    ADDRESS_2,
)
from leap.keymanager import openpgp, errors


# some regexps
IP_REGEX = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}" + \
    "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
HOSTNAME_REGEX = "(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*" + \
    "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])"
IP_OR_HOST_REGEX = '(' + IP_REGEX + '|' + HOSTNAME_REGEX + ')'


class TestSmtpGateway(TestCaseWithKeyManager):

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

    def assertMatch(self, string, pattern, msg=None):
        if not re.match(pattern, string):
            msg = self._formatMessage(msg, '"%s" does not match pattern "%s".'
                                           % (string, pattern))
            raise self.failureException(msg)

    @inlineCallbacks
    def test_gateway_accepts_valid_email(self):
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

        # XXX this bit can be refactored away in a helper
        # method...
        proto = SMTPFactory(
            u'anotheruser@leap.se',
            self._km,
            self._config['encrypted_only'],
            outgoing_mail=Mock()).buildProtocol(('127.0.0.1', 0))
        # snip...
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        reply = ""
        for i, line in enumerate(self.EMAIL_DATA):
            reply += yield self.getReply(line + '\r\n', proto, transport)
        self.assertMatch(reply, '\r\n'.join(SMTP_ANSWERS),
                         'Did not get expected answer from gateway.')
        proto.setTimeout(None)

    @inlineCallbacks
    def test_missing_key_rejects_address(self):
        """
        Test if server rejects to send unencrypted when 'encrypted_only' is
        True.
        """
        # remove key from key manager
        pubkey = yield self._km.get_key(ADDRESS, openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.GPG_BINARY_PATH)
        yield pgp.delete_key(pubkey)
        # mock the key fetching
        self._km._fetch_keys_from_server = Mock(
            return_value=fail(errors.KeyNotFound()))
        # prepare the SMTP factory
        proto = SMTPFactory(
            u'anotheruser@leap.se',
            self._km,
            self._config['encrypted_only'],
            outgoing_mail=Mock()).buildProtocol(('127.0.0.1', 0))
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        yield self.getReply(self.EMAIL_DATA[0] + '\r\n', proto, transport)
        yield self.getReply(self.EMAIL_DATA[1] + '\r\n', proto, transport)
        reply = yield self.getReply(self.EMAIL_DATA[2] + '\r\n',
                                    proto, transport)
        # ensure the address was rejected
        self.assertEqual(
            '550 Cannot receive for specified address\r\n',
            reply,
            'Address should have been rejecetd with appropriate message.')
        proto.setTimeout(None)

    @inlineCallbacks
    def test_missing_key_accepts_address(self):
        """
        Test if server accepts to send unencrypted when 'encrypted_only' is
        False.
        """
        # remove key from key manager
        pubkey = yield self._km.get_key(ADDRESS, openpgp.OpenPGPKey)
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.GPG_BINARY_PATH)
        yield pgp.delete_key(pubkey)
        # mock the key fetching
        self._km._fetch_keys_from_server = Mock(
            return_value=fail(errors.KeyNotFound()))
        # prepare the SMTP factory with encrypted only equal to false
        proto = SMTPFactory(
            u'anotheruser@leap.se',
            self._km,
            False, outgoing_mail=Mock()).buildProtocol(('127.0.0.1', 0))
        transport = proto_helpers.StringTransport()
        proto.makeConnection(transport)
        yield self.getReply(self.EMAIL_DATA[0] + '\r\n', proto, transport)
        yield self.getReply(self.EMAIL_DATA[1] + '\r\n', proto, transport)
        reply = yield self.getReply(self.EMAIL_DATA[2] + '\r\n',
                                    proto, transport)
        # ensure the address was accepted
        self.assertEqual(
            '250 Recipient address accepted\r\n',
            reply,
            'Address should have been accepted with appropriate message.')
        proto.setTimeout(None)

    def getReply(self, line, proto, transport):
        proto.lineReceived(line)

        if line[:4] not in ['HELO', 'MAIL', 'RCPT', 'DATA']:
            return succeed("")

        def check_transport(_):
            reply = transport.value()
            if reply:
                transport.clear()
                return succeed(reply)

            d = Deferred()
            d.addCallback(check_transport)
            reactor.callLater(0, lambda: d.callback(None))
            return d

        return check_transport(None)
