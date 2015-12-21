# -*- coding: utf-8 -*-
# test_migrator.py
# Copyright (C) 2015 LEAP
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
Tests for the migrator.
"""


from collections import namedtuple
from mock import Mock
from twisted.internet.defer import succeed, inlineCallbacks

from leap.keymanager.migrator import KeyDocumentsMigrator, KEY_ID_KEY
from leap.keymanager.keys import (
    TAGS_PRIVATE_INDEX,
    KEYMANAGER_ACTIVE_TAG,
    KEYMANAGER_KEY_TAG,
    KEYMANAGER_DOC_VERSION,

    KEY_ADDRESS_KEY,
    KEY_UIDS_KEY,
    KEY_VERSION_KEY,
    KEY_FINGERPRINT_KEY,
    KEY_VALIDATION_KEY,
    KEY_LAST_AUDITED_AT_KEY,
    KEY_ENCR_USED_KEY,
    KEY_SIGN_USED_KEY,
)
from leap.keymanager.validation import ValidationLevels
from leap.keymanager.tests import (
    KeyManagerWithSoledadTestCase,
    ADDRESS,
    ADDRESS_2,
    KEY_FINGERPRINT,
)


class OpenPGPCryptoTestCase(KeyManagerWithSoledadTestCase):
    @inlineCallbacks
    def test_simple_migration(self):
        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc
        put_doc = self._soledad.put_doc

        def my_get_from_index(*args):
            docs = []
            if (args[0] == TAGS_PRIVATE_INDEX and
                    args[2] == '0'):
                SoledadDocument = namedtuple("SoledadDocument", ["content"])
                if args[1] == KEYMANAGER_KEY_TAG:
                    docs = [SoledadDocument({
                        KEY_ADDRESS_KEY: [ADDRESS],
                        KEY_ID_KEY: KEY_FINGERPRINT[-16:],
                        KEY_FINGERPRINT_KEY: KEY_FINGERPRINT,
                        KEY_VALIDATION_KEY: str(ValidationLevels.Weak_Chain),
                        KEY_LAST_AUDITED_AT_KEY: 0,
                        KEY_ENCR_USED_KEY: True,
                        KEY_SIGN_USED_KEY: False,
                    })]
                if args[1] == KEYMANAGER_ACTIVE_TAG:
                    docs = [SoledadDocument({
                        KEY_ID_KEY: KEY_FINGERPRINT[-16:],
                    })]
            return succeed(docs)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))
        self._soledad.put_doc = Mock(return_value=succeed(None))

        try:
            migrator = KeyDocumentsMigrator(self._soledad)
            yield migrator.migrate()
            call_list = self._soledad.put_doc.call_args_list
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc
            self._soledad.put_doc = put_doc

        self.assertEqual(len(call_list), 2)
        active = call_list[0][0][0]
        key = call_list[1][0][0]

        self.assertTrue(KEY_ID_KEY not in active.content)
        self.assertEqual(active.content[KEY_VERSION_KEY],
                         KEYMANAGER_DOC_VERSION)
        self.assertEqual(active.content[KEY_FINGERPRINT_KEY], KEY_FINGERPRINT)
        self.assertEqual(active.content[KEY_VALIDATION_KEY],
                         str(ValidationLevels.Weak_Chain))
        self.assertEqual(active.content[KEY_LAST_AUDITED_AT_KEY], 0)
        self.assertEqual(active.content[KEY_ENCR_USED_KEY], True)
        self.assertEqual(active.content[KEY_SIGN_USED_KEY], False)

        self.assertTrue(KEY_ID_KEY not in key.content)
        self.assertTrue(KEY_ADDRESS_KEY not in key.content)
        self.assertTrue(KEY_VALIDATION_KEY not in key.content)
        self.assertTrue(KEY_LAST_AUDITED_AT_KEY not in key.content)
        self.assertTrue(KEY_ENCR_USED_KEY not in key.content)
        self.assertTrue(KEY_SIGN_USED_KEY not in key.content)
        self.assertEqual(key.content[KEY_UIDS_KEY], [ADDRESS])

    @inlineCallbacks
    def test_two_active_docs(self):
        get_from_index = self._soledad.get_from_index
        delete_doc = self._soledad.delete_doc
        put_doc = self._soledad.put_doc

        def my_get_from_index(*args):
            docs = []
            if (args[0] == TAGS_PRIVATE_INDEX and
                    args[2] == '0'):
                SoledadDocument = namedtuple("SoledadDocument", ["content"])
                if args[1] == KEYMANAGER_KEY_TAG:
                    validation = str(ValidationLevels.Provider_Trust)
                    docs = [SoledadDocument({
                        KEY_ADDRESS_KEY: [ADDRESS, ADDRESS_2],
                        KEY_ID_KEY: KEY_FINGERPRINT[-16:],
                        KEY_FINGERPRINT_KEY: KEY_FINGERPRINT,
                        KEY_VALIDATION_KEY: validation,
                        KEY_LAST_AUDITED_AT_KEY: 1984,
                        KEY_ENCR_USED_KEY: True,
                        KEY_SIGN_USED_KEY: False,
                    })]
                if args[1] == KEYMANAGER_ACTIVE_TAG:
                    docs = [
                        SoledadDocument({
                            KEY_ADDRESS_KEY: ADDRESS,
                            KEY_ID_KEY: KEY_FINGERPRINT[-16:],
                        }),
                        SoledadDocument({
                            KEY_ADDRESS_KEY: ADDRESS_2,
                            KEY_ID_KEY: KEY_FINGERPRINT[-16:],
                        }),
                    ]
            return succeed(docs)

        self._soledad.get_from_index = my_get_from_index
        self._soledad.delete_doc = Mock(return_value=succeed(None))
        self._soledad.put_doc = Mock(return_value=succeed(None))

        try:
            migrator = KeyDocumentsMigrator(self._soledad)
            yield migrator.migrate()
            call_list = self._soledad.put_doc.call_args_list
        finally:
            self._soledad.get_from_index = get_from_index
            self._soledad.delete_doc = delete_doc
            self._soledad.put_doc = put_doc

        self.assertEqual(len(call_list), 3)
        for active in [call[0][0] for call in call_list][:2]:
            self.assertTrue(KEY_ID_KEY not in active.content)
            self.assertEqual(active.content[KEY_VERSION_KEY],
                             KEYMANAGER_DOC_VERSION)
            self.assertEqual(active.content[KEY_FINGERPRINT_KEY],
                             KEY_FINGERPRINT)
            self.assertEqual(active.content[KEY_VALIDATION_KEY],
                             str(ValidationLevels.Weak_Chain))
            self.assertEqual(active.content[KEY_LAST_AUDITED_AT_KEY], 0)
            self.assertEqual(active.content[KEY_ENCR_USED_KEY], False)
            self.assertEqual(active.content[KEY_SIGN_USED_KEY], False)
