# -*- coding: utf-8 -*-
# test_incoming_mail.py
# Copyright (C) 2015-2016 LEAP
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
Test case for leap.bitmask.mail.incoming.service

@authors: Ruben Pollan, <meskio@sindominio.net>

@license: GPLv3, see included LICENSE file
"""
import json
import os
import tempfile
import uuid

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.parser import Parser
from mock import Mock

from twisted.internet import defer
from twisted.python import log

from leap.bitmask.keymanager.errors import KeyAddressMismatch
from leap.bitmask.mail.adaptors import soledad_indexes as fields
from leap.bitmask.mail.adaptors.soledad import cleanup_deferred_locks
from leap.bitmask.mail.adaptors.soledad import SoledadMailAdaptor
from leap.bitmask.mail.mail import MessageCollection
from leap.bitmask.mail.mailbox_indexer import MailboxIndexer

from leap.bitmask.mail.incoming.service import IncomingMail
from leap.bitmask.mail.rfc3156 import MultipartEncrypted, PGPEncrypted
from leap.bitmask.mail.testing import KeyManagerWithSoledadTestCase
from leap.bitmask.mail.testing import ADDRESS, ADDRESS_2
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.crypto import (
    EncryptionSchemes,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
)

HERE = os.path.split(os.path.abspath(__file__))[0]

# TODO: add some tests for encrypted, unencrypted, signed and unsgined messages


class IncomingMailTestCase(KeyManagerWithSoledadTestCase):
    """
    Tests for the incoming mail parser
    """
    NICKSERVER = "http://domain"
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
        "from": ADDRESS_2,
        "to": ADDRESS,
        "body": BODY
    }

    def setUp(self):
        cleanup_deferred_locks()
        try:
            del self._soledad
            del self.km
        except AttributeError:
            pass

        # pytest handles correctly the setupEnv for the class,
        # but trial ignores it.
        if not getattr(self, 'tempdir', None):
            self.tempdir = tempfile.mkdtemp()

        def getCollection(_):
            adaptor = SoledadMailAdaptor()
            store = self._soledad
            adaptor.store = store
            mbox_indexer = MailboxIndexer(store)
            mbox_name = "INBOX"
            mbox_uuid = str(uuid.uuid4())

            def get_collection_from_mbox_wrapper(wrapper):
                wrapper.uuid = mbox_uuid
                return MessageCollection(
                    adaptor, store,
                    mbox_indexer=mbox_indexer, mbox_wrapper=wrapper)

            d = adaptor.initialize_store(store)
            d.addCallback(lambda _: mbox_indexer.create_table(mbox_uuid))
            d.addCallback(
                lambda _: adaptor.get_or_create_mbox(store, mbox_name))
            d.addCallback(get_collection_from_mbox_wrapper)
            return d

        def setUpFetcher(inbox_collection):
            self.fetcher = IncomingMail(
                self.km,
                self._soledad,
                inbox_collection,
                ADDRESS)

            # The messages don't exist on soledad will fail on deletion
            self.fetcher._delete_incoming_message = Mock(
                return_value=defer.succeed(None))

        d = KeyManagerWithSoledadTestCase.setUp(self)
        d.addCallback(getCollection)
        d.addCallback(setUpFetcher)
        d.addErrback(log.err)
        return d

    def tearDown(self):
        d = KeyManagerWithSoledadTestCase.tearDown(self)
        return d

    def testExtractOpenPGPHeader(self):
        """
        Test the OpenPGP header key extraction
        """
        KEYURL = "https://leap.se/key.txt"
        OpenPGP = "id=12345678; url=\"%s\"; preference=signencrypt" % (KEYURL,)

        message = Parser().parsestr(self.EMAIL)
        message.add_header("OpenPGP", OpenPGP)
        self.fetcher._keymanager.fetch_key = Mock(
            return_value=defer.succeed(None))

        def fetch_key_called(ret):
            self.fetcher._keymanager.fetch_key.assert_called_once_with(
                ADDRESS_2, KEYURL)

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
        KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."

        message = MIMEMultipart()
        message.add_header("from", ADDRESS_2)
        key = MIMEApplication("", "pgp-keys")
        key.set_payload(KEY)
        message.attach(key)
        self.fetcher._keymanager.put_raw_key = Mock(
            return_value=defer.succeed(None))

        def put_raw_key_called(_):
            self.fetcher._keymanager.put_raw_key.assert_called_once_with(
                KEY, address=ADDRESS_2)

        d = self._do_fetch(message.as_string())
        d.addCallback(put_raw_key_called)
        return d

    def testExtractInvalidAttachedKey(self):
        KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."

        message = MIMEMultipart()
        message.add_header("from", ADDRESS_2)
        key = MIMEApplication("", "pgp-keys")
        key.set_payload(KEY)
        message.attach(key)
        self.fetcher._keymanager.put_raw_key = Mock(
            return_value=defer.fail(KeyAddressMismatch()))

        def put_raw_key_called(_):
            self.fetcher._keymanager.put_raw_key.assert_called_once_with(
                KEY, address=ADDRESS_2)

        d = self._do_fetch(message.as_string())
        d.addCallback(put_raw_key_called)
        d.addErrback(log.err)
        return d

    def testExtractAttachedKeyAndNotOpenPGPHeader(self):
        KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
        KEYURL = "https://leap.se/key.txt"
        OpenPGP = "id=12345678; url=\"%s\"; preference=signencrypt" % (KEYURL,)

        message = MIMEMultipart()
        message.add_header("from", ADDRESS_2)
        message.add_header("OpenPGP", OpenPGP)
        key = MIMEApplication("", "pgp-keys")
        key.set_payload(KEY)
        message.attach(key)

        self.fetcher._keymanager.put_raw_key = Mock(
            return_value=defer.succeed(None))
        self.fetcher._keymanager.fetch_key = Mock()

        def put_raw_key_called(_):
            self.fetcher._keymanager.put_raw_key.assert_called_once_with(
                KEY, address=ADDRESS_2)
            self.assertFalse(self.fetcher._keymanager.fetch_key.called)

        d = self._do_fetch(message.as_string())
        d.addCallback(put_raw_key_called)
        return d

    def testExtractOpenPGPHeaderIfInvalidAttachedKey(self):
        KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
        KEYURL = "https://leap.se/key.txt"
        OpenPGP = "id=12345678; url=\"%s\"; preference=signencrypt" % (KEYURL,)

        message = MIMEMultipart()
        message.add_header("from", ADDRESS_2)
        message.add_header("OpenPGP", OpenPGP)
        key = MIMEApplication("", "pgp-keys")
        key.set_payload(KEY)
        message.attach(key)

        self.fetcher._keymanager.put_raw_key = Mock(
            return_value=defer.fail(KeyAddressMismatch()))
        self.fetcher._keymanager.fetch_key = Mock()

        def put_raw_key_called(_):
            self.fetcher._keymanager.put_raw_key.assert_called_once_with(
                KEY, address=ADDRESS_2)
            self.fetcher._keymanager.fetch_key.assert_called_once_with(
                ADDRESS_2, KEYURL)

        d = self._do_fetch(message.as_string())
        d.addCallback(put_raw_key_called)
        return d

    def testAddDecryptedHeader(self):
        class DummyMsg():

            def __init__(self):
                self.headers = {}

            def add_header(self, k, v):
                self.headers[k] = v

        msg = DummyMsg()
        self.fetcher._add_decrypted_header(msg)

        self.assertEquals(msg.headers['X-Leap-Encryption'], 'decrypted')

    def testDecryptEmail(self):

        self.fetcher._decryption_error = Mock()
        self.fetcher._add_decrypted_header = Mock()

        def create_encrypted_message(encstr):
            message = Parser().parsestr(self.EMAIL)
            newmsg = MultipartEncrypted('application/pgp-encrypted')
            for hkey, hval in message.items():
                newmsg.add_header(hkey, hval)

            encmsg = MIMEApplication(
                encstr, _subtype='octet-stream', _encoder=lambda x: x)
            encmsg.add_header('content-disposition', 'attachment',
                              filename='msg.asc')
            # create meta message
            metamsg = PGPEncrypted()
            metamsg.add_header('Content-Disposition', 'attachment')
            # attach pgp message parts to new message
            newmsg.attach(metamsg)
            newmsg.attach(encmsg)
            return newmsg

        def decryption_error_not_called(_):
            self.assertFalse(self.fetcher._decryption_error.called,
                             "There was some errors with decryption")

        def add_decrypted_header_called(_):
            self.assertTrue(self.fetcher._add_decrypted_header.called,
                            "There was some errors with decryption")

        d = self.km.encrypt(self.EMAIL, ADDRESS, sign=ADDRESS_2)
        d.addCallback(create_encrypted_message)
        d.addCallback(
            lambda message:
            self._do_fetch(message.as_string()))
        d.addCallback(decryption_error_not_called)
        d.addCallback(add_decrypted_header_called)
        return d

    def testValidateSignatureFromEncryptedEmailFromAppleMail(self):
        enc_signed_file = os.path.join(
            HERE, 'rfc822.multi-encrypt-signed.message')
        self.fetcher._add_verified_signature_header = Mock()

        def add_verified_signature_header_called(_):
            self.assertTrue(self.fetcher._add_verified_signature_header.called,
                            "There was some errors verifying signature")

        with open(enc_signed_file) as f:
            enc_signed_raw = f.read()

        d = self._do_fetch(enc_signed_raw)
        d.addCallback(add_verified_signature_header_called)
        return d

    def testListener(self):
        self.called = False

        def listener(uid):
            self.called = True

        def listener_called(_):
            self.assertTrue(self.called)

        self.fetcher.add_listener(listener)
        d = self._do_fetch(self.EMAIL)
        d.addCallback(listener_called)
        return d

    def _do_fetch(self, message):
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
        d = self.km.encrypt(data, ADDRESS, fetch_remote=False)
        d.addCallback(set_email_content)
        return d

    def _mock_soledad_get_from_index(self, index_name, value):
        get_from_index = self._soledad.get_from_index

        def soledad_mock(idx_name, *key_values):
            if index_name == idx_name:
                return defer.succeed(value)
            return get_from_index(idx_name, *key_values)
        self.fetcher._soledad.get_from_index = Mock(side_effect=soledad_mock)
