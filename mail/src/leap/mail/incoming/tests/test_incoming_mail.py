# -*- coding: utf-8 -*-
# test_incoming_mail.py
# Copyright (C) 2015 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test case for leap.mail.incoming.service

@authors: Ruben Pollan, <meskio@sindominio.net>

@license: GPLv3, see included LICENSE file
"""

import json

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.parser import Parser
from mock import Mock
from twisted.internet import defer

from leap.keymanager.openpgp import OpenPGPKey
from leap.mail.adaptors import soledad_indexes as fields
from leap.mail.constants import INBOX_NAME
from leap.mail.imap.account import IMAPAccount
from leap.mail.incoming.service import IncomingMail
from leap.mail.tests import (
    TestCaseWithKeyManager,
    ADDRESS,
)
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.crypto import (
    EncryptionSchemes,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
)


class IncomingMailTestCase(TestCaseWithKeyManager):
    """
    Tests for the incoming mail parser
    """
    NICKSERVER = "http://domain"
    FROM_ADDRESS = "test@somedomain.com"
    BODY = """
Governments of the Industrial World, you weary giants of flesh and steel, I
come from Cyberspace, the new home of Mind. On behalf of the future, I ask
you of the past to leave us alone. You are not welcome among us. You have
no sovereignty where we gather.
    """
    EMAIL = """from: Test from SomeDomain <%(from)s>
to: %(to)s
subject: independence of cyberspace

%(body)s
    """ % {
        "from": FROM_ADDRESS,
        "to": ADDRESS,
        "body": BODY
    }

    def setUp(self):
        def getInbox(_):
            theAccount = IMAPAccount(ADDRESS, self._soledad)
            return theAccount.callWhenReady(
                lambda _: theAccount.getMailbox(INBOX_NAME))

        def setUpFetcher(inbox):
            # Soledad sync makes trial block forever. The sync it's mocked to
            # fix this problem. _mock_soledad_get_from_index can be used from
            # the tests to provide documents.
            self._soledad.sync = Mock()

            self.fetcher = IncomingMail(
                self._km,
                self._soledad,
                inbox,
                ADDRESS)

        d = super(IncomingMailTestCase, self).setUp()
        d.addCallback(getInbox)
        d.addCallback(setUpFetcher)
        return d

    def tearDown(self):
        del self.fetcher
        return super(IncomingMailTestCase, self).tearDown()

    def testExtractOpenPGPHeader(self):
        """
        Test the OpenPGP header key extraction
        """
        KEYURL = "https://somedomain.com/key.txt"
        OpenPGP = "id=12345678; url=\"%s\"; preference=signencrypt" % (KEYURL,)

        message = Parser().parsestr(self.EMAIL)
        message.add_header("OpenPGP", OpenPGP)
        self.fetcher._keymanager.fetch_key = Mock(
            return_value=defer.succeed(None))

        def fetch_key_called(ret):
            self.fetcher._keymanager.fetch_key.assert_called_once_with(
                self.FROM_ADDRESS, KEYURL, OpenPGPKey)

        d = self._create_incoming_email(message.as_string())
        d.addCallback(
            lambda email:
            self._mock_soledad_get_from_index(fields.JUST_MAIL_IDX, [email]))
        d.addCallback(lambda _: self.fetcher.fetch())
        d.addCallback(fetch_key_called)
        return d

    def testExtractOpenPGPHeaderInvalidUrl(self):
        """
        Test the OpenPGP header key extraction
        """
        KEYURL = "https://someotherdomain.com/key.txt"
        OpenPGP = "id=12345678; url=\"%s\"; preference=signencrypt" % (KEYURL,)

        message = Parser().parsestr(self.EMAIL)
        message.add_header("OpenPGP", OpenPGP)
        self.fetcher._keymanager.fetch_key = Mock()

        def fetch_key_called(ret):
            self.assertFalse(self.fetcher._keymanager.fetch_key.called)

        d = self._create_incoming_email(message.as_string())
        d.addCallback(
            lambda email:
            self._mock_soledad_get_from_index(fields.JUST_MAIL_IDX, [email]))
        d.addCallback(lambda _: self.fetcher.fetch())
        d.addCallback(fetch_key_called)
        return d

    def testExtractAttachedKey(self):
        """
        Test the OpenPGP header key extraction
        """
        KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."

        message = MIMEMultipart()
        message.add_header("from", self.FROM_ADDRESS)
        key = MIMEApplication("", "pgp-keys")
        key.set_payload(KEY)
        message.attach(key)
        self.fetcher._keymanager.put_raw_key = Mock(
            return_value=defer.succeed(None))

        def put_raw_key_called(_):
            self.fetcher._keymanager.put_raw_key.assert_called_once_with(
                KEY, OpenPGPKey, address=self.FROM_ADDRESS)

        d = self._mock_fetch(message.as_string())
        d.addCallback(put_raw_key_called)
        return d

    def _mock_fetch(self, message):
        self.fetcher._keymanager.fetch_key = Mock()
        d = self._create_incoming_email(message)
        d.addCallback(
            lambda email:
            self._mock_soledad_get_from_index(fields.JUST_MAIL_IDX, [email]))
        d.addCallback(lambda _: self.fetcher.fetch())
        return d

    def _create_incoming_email(self, email_str):
        email = SoledadDocument()
        data = json.dumps(
            {"incoming": True, "content": email_str},
            ensure_ascii=False)

        def set_email_content(encr_data):
            email.content = {
                fields.INCOMING_KEY: True,
                fields.ERROR_DECRYPTING_KEY: False,
                ENC_SCHEME_KEY: EncryptionSchemes.PUBKEY,
                ENC_JSON_KEY: encr_data
            }
            return email
        d = self._km.encrypt(data, ADDRESS, OpenPGPKey, fetch_remote=False)
        d.addCallback(set_email_content)
        return d

    def _mock_soledad_get_from_index(self, index_name, value):
        get_from_index = self._soledad.get_from_index

        def soledad_mock(idx_name, *key_values):
            if index_name == idx_name:
                return defer.succeed(value)
            return get_from_index(idx_name, *key_values)
        self.fetcher._soledad.get_from_index = Mock(side_effect=soledad_mock)
