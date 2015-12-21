# -*- coding: utf-8 -*-
# migrator.py
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
Document migrator
"""
# XXX: versioning has being added 12/2015 when keymanager was not
#      much in use in the wild. We can probably drop support for
#      keys without version at some point.


from collections import namedtuple
from twisted.internet.defer import gatherResults, succeed

from leap.keymanager.keys import (
    TAGS_PRIVATE_INDEX,
    KEYMANAGER_KEY_TAG,
    KEYMANAGER_ACTIVE_TAG,

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


KEY_ID_KEY = 'key_id'

KeyDocs = namedtuple("KeyDocs", ['key', 'active'])


class KeyDocumentsMigrator(object):
    """
    Migrate old KeyManager Soledad Documents to the newest schema
    """

    def __init__(self, soledad):
        self._soledad = soledad

    def migrate(self):
        deferred_public = self._get_docs(private=False)
        deferred_public.addCallback(self._migrate_docs)

        deferred_private = self._get_docs(private=True)
        deferred_private.addCallback(self._migrate_docs)

        return gatherResults([deferred_public, deferred_private])

    def _get_docs(self, private=False):
        private_value = '1' if private else '0'

        deferred_keys = self._soledad.get_from_index(
            TAGS_PRIVATE_INDEX,
            KEYMANAGER_KEY_TAG,
            private_value)
        deferred_active = self._soledad.get_from_index(
            TAGS_PRIVATE_INDEX,
            KEYMANAGER_ACTIVE_TAG,
            private_value)
        return gatherResults([deferred_keys, deferred_active])

    def _migrate_docs(self, (key_docs, active_docs)):
        def update_keys(keys):
            deferreds = []
            for key_id in keys:
                key = keys[key_id].key
                actives = keys[key_id].active

                d = self._migrate_actives(key, actives)
                deferreds.append(d)

                d = self._migrate_key(key)
                deferreds.append(d)
            return gatherResults(deferreds)

        d = self._buildKeyDict(key_docs, active_docs)
        d.addCallback(lambda keydict: self._filter_outdated(keydict))
        d.addCallback(update_keys)

    def _buildKeyDict(self, keys, actives):
        keydict = {
            fp2id(key.content[KEY_FINGERPRINT_KEY]): KeyDocs(key, [])
            for key in keys}

        deferreds = []
        for active in actives:
            if KEY_ID_KEY in active.content:
                key_id = active.content[KEY_ID_KEY]
                if key_id not in keydict:
                    d = self._soledad.delete_doc(active)
                    deferreds.append(d)
                    continue
                keydict[key_id].active.append(active)

        d = gatherResults(deferreds)
        d.addCallback(lambda _: keydict)
        return d

    def _filter_outdated(self, keydict):
        outdated = {}
        for key_id, docs in keydict.items():
            if ((docs.key and KEY_VERSION_KEY not in docs.key.content) or
                    docs.active):
                outdated[key_id] = docs
        return outdated

    def _migrate_actives(self, key, actives):
        if not key:
            deferreds = []
            for active in actives:
                d = self._soledad.delete_doc(active)
                deferreds.append(d)
            return gatherResults(deferreds)

        validation = str(ValidationLevels.Weak_Chain)
        last_audited = 0
        encr_used = False
        sign_used = False
        fingerprint = key.content[KEY_FINGERPRINT_KEY]
        if len(actives) == 1 and KEY_VERSION_KEY not in key.content:
            # we can preserve the validation of the key if there is only one
            # active address for the key
            validation = key.content[KEY_VALIDATION_KEY]
            last_audited = key.content[KEY_LAST_AUDITED_AT_KEY]
            encr_used = key.content[KEY_ENCR_USED_KEY]
            sign_used = key.content[KEY_SIGN_USED_KEY]

        deferreds = []
        for active in actives:
            if KEY_VERSION_KEY in active.content:
                continue

            active.content[KEY_VERSION_KEY] = KEYMANAGER_DOC_VERSION
            active.content[KEY_FINGERPRINT_KEY] = fingerprint
            active.content[KEY_VALIDATION_KEY] = validation
            active.content[KEY_LAST_AUDITED_AT_KEY] = last_audited
            active.content[KEY_ENCR_USED_KEY] = encr_used
            active.content[KEY_SIGN_USED_KEY] = sign_used
            del active.content[KEY_ID_KEY]
            d = self._soledad.put_doc(active)
            deferreds.append(d)
        return gatherResults(deferreds)

    def _migrate_key(self, key):
        if not key or KEY_VERSION_KEY in key.content:
            return succeed(None)

        key.content[KEY_VERSION_KEY] = KEYMANAGER_DOC_VERSION
        key.content[KEY_UIDS_KEY] = key.content[KEY_ADDRESS_KEY]
        del key.content[KEY_ADDRESS_KEY]
        del key.content[KEY_ID_KEY]
        del key.content[KEY_VALIDATION_KEY]
        del key.content[KEY_LAST_AUDITED_AT_KEY]
        del key.content[KEY_ENCR_USED_KEY]
        del key.content[KEY_SIGN_USED_KEY]
        return self._soledad.put_doc(key)


def fp2id(fingerprint):
    KEY_ID_LENGTH = 16
    return fingerprint[-KEY_ID_LENGTH:]
