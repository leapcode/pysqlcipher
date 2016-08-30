# -*- coding: utf-8 -*-
# documents.py
# Copyright (C) 2013-2016 LEAP
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
Soledad documents
"""
from twisted.internet import defer
from leap.common.check import leap_assert

#
# Dictionary keys used for storing cryptographic keys.
#

KEY_VERSION_KEY = 'version'
KEY_UIDS_KEY = 'uids'
KEY_ADDRESS_KEY = 'address'
KEY_TYPE_KEY = 'type'
KEY_FINGERPRINT_KEY = 'fingerprint'
KEY_DATA_KEY = 'key_data'
KEY_PRIVATE_KEY = 'private'
KEY_LENGTH_KEY = 'length'
KEY_EXPIRY_DATE_KEY = 'expiry_date'
KEY_LAST_AUDITED_AT_KEY = 'last_audited_at'
KEY_REFRESHED_AT_KEY = 'refreshed_at'
KEY_VALIDATION_KEY = 'validation'
KEY_ENCR_USED_KEY = 'encr_used'
KEY_SIGN_USED_KEY = 'sign_used'
KEY_TAGS_KEY = 'tags'


#
# Key storage constants
#

KEYMANAGER_KEY_TAG = 'keymanager-key'
KEYMANAGER_ACTIVE_TAG = 'keymanager-active'
KEYMANAGER_ACTIVE_TYPE = '-active'

# Version of the Soledad Document schema,
# it should be bumped each time the document format changes
KEYMANAGER_DOC_VERSION = 1


#
# key indexing constants.
#

TAGS_PRIVATE_INDEX = 'by-tags-private'
TYPE_FINGERPRINT_PRIVATE_INDEX = 'by-type-fingerprint-private'
TYPE_ADDRESS_PRIVATE_INDEX = 'by-type-address-private'
INDEXES = {
    TAGS_PRIVATE_INDEX: [
        KEY_TAGS_KEY,
        'bool(%s)' % KEY_PRIVATE_KEY,
    ],
    TYPE_FINGERPRINT_PRIVATE_INDEX: [
        KEY_TYPE_KEY,
        KEY_FINGERPRINT_KEY,
        'bool(%s)' % KEY_PRIVATE_KEY,
    ],
    TYPE_ADDRESS_PRIVATE_INDEX: [
        KEY_TYPE_KEY,
        KEY_ADDRESS_KEY,
        'bool(%s)' % KEY_PRIVATE_KEY,
    ]
}


@defer.inlineCallbacks
def init_indexes(soledad):
    """
    Initialize the database indexes.
    """
    leap_assert(soledad is not None,
                "Cannot init indexes with null soledad")

    indexes = yield soledad.list_indexes()
    db_indexes = dict(indexes)
    # Loop through the indexes we expect to find.
    for name, expression in INDEXES.items():
        if name not in db_indexes:
            # The index does not yet exist.
            yield soledad.create_index(name, *expression)
        elif expression != db_indexes[name]:
            # The index exists but the definition is not what expected,
            # so we delete it and add the proper index expression.
            yield soledad.delete_index(name)
            yield soledad.create_index(name, *expression)
