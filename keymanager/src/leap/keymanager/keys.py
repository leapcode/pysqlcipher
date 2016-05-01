# -*- coding: utf-8 -*-
# keys.py
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
Abstact key type and encryption scheme representations.
"""


try:
    import simplejson as json
except ImportError:
    import json  # noqa
import logging
import re
import time


from abc import ABCMeta
from datetime import datetime
from leap.common.check import leap_assert
from twisted.internet import defer

from leap.keymanager.validation import ValidationLevels

logger = logging.getLogger(__name__)


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


#
# Key handling utilities
#

def is_address(address):
    """
    Return whether the given C{address} is in the form user@provider.

    :param address: The address to be tested.
    :type address: str
    :return: Whether C{address} is in the form user@provider.
    :rtype: bool
    """
    return bool(re.match('[\w.-]+@[\w.-]+', address))


def build_key_from_dict(kClass, key, active=None):
    """
    Build an C{kClass} key based on info in C{kdict}.

    :param key: Dictionary with key data.
    :type key: dict
    :param active: Dictionary with active data.
    :type active: dict
    :return: An instance of the key.
    :rtype: C{kClass}
    """
    address = None
    validation = ValidationLevels.Weak_Chain
    last_audited_at = None
    encr_used = False
    sign_used = False

    if active:
        address = active[KEY_ADDRESS_KEY]
        try:
            validation = ValidationLevels.get(active[KEY_VALIDATION_KEY])
        except ValueError:
            logger.error("Not valid validation level (%s) for key %s",
                         (active[KEY_VALIDATION_KEY],
                          active[KEY_FINGERPRINT_KEY]))
        last_audited_at = _to_datetime(active[KEY_LAST_AUDITED_AT_KEY])
        encr_used = active[KEY_ENCR_USED_KEY]
        sign_used = active[KEY_SIGN_USED_KEY]

    expiry_date = _to_datetime(key[KEY_EXPIRY_DATE_KEY])
    refreshed_at = _to_datetime(key[KEY_REFRESHED_AT_KEY])

    return kClass(
        address=address,
        uids=key[KEY_UIDS_KEY],
        fingerprint=key[KEY_FINGERPRINT_KEY],
        key_data=key[KEY_DATA_KEY],
        private=key[KEY_PRIVATE_KEY],
        length=key[KEY_LENGTH_KEY],
        expiry_date=expiry_date,
        last_audited_at=last_audited_at,
        refreshed_at=refreshed_at,
        validation=validation,
        encr_used=encr_used,
        sign_used=sign_used,
    )


def _to_datetime(unix_time):
    if unix_time != 0:
        return datetime.fromtimestamp(unix_time)
    else:
        return None


def _to_unix_time(date):
    if date is not None:
        return int(time.mktime(date.timetuple()))
    else:
        return 0


#
# Abstraction for encryption keys
#

class EncryptionKey(object):
    """
    Abstract class for encryption keys.

    A key is "validated" if the nicknym agent has bound the user address to a
    public key.
    """

    __metaclass__ = ABCMeta

    __slots__ = ('address', 'uids', 'fingerprint', 'key_data',
                 'private', 'length', 'expiry_date', 'validation',
                 'last_audited_at', 'refreshed_at',
                 'encr_used', 'sign_used', '_index')

    def __init__(self, address=None, uids=[], fingerprint="",
                 key_data="", private=False, length=0, expiry_date=None,
                 validation=ValidationLevels.Weak_Chain, last_audited_at=None,
                 refreshed_at=None, encr_used=False, sign_used=False):
        self.address = address
        if not uids and address:
            self.uids = [address]
        else:
            self.uids = uids
        self.fingerprint = fingerprint
        self.key_data = key_data
        self.private = private
        self.length = length
        self.expiry_date = expiry_date

        self.validation = validation
        self.last_audited_at = last_audited_at
        self.refreshed_at = refreshed_at
        self.encr_used = encr_used
        self.sign_used = sign_used
        self._index = len(self.__slots__)

    def get_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        expiry_date = _to_unix_time(self.expiry_date)
        refreshed_at = _to_unix_time(self.refreshed_at)

        return json.dumps({
            KEY_UIDS_KEY: self.uids,
            KEY_TYPE_KEY: self.__class__.__name__,
            KEY_FINGERPRINT_KEY: self.fingerprint,
            KEY_DATA_KEY: self.key_data,
            KEY_PRIVATE_KEY: self.private,
            KEY_LENGTH_KEY: self.length,
            KEY_EXPIRY_DATE_KEY: expiry_date,
            KEY_REFRESHED_AT_KEY: refreshed_at,
            KEY_VERSION_KEY: KEYMANAGER_DOC_VERSION,
            KEY_TAGS_KEY: [KEYMANAGER_KEY_TAG],
        })

    def get_active_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        last_audited_at = _to_unix_time(self.last_audited_at)

        return json.dumps({
            KEY_ADDRESS_KEY: self.address,
            KEY_TYPE_KEY: self.__class__.__name__ + KEYMANAGER_ACTIVE_TYPE,
            KEY_FINGERPRINT_KEY: self.fingerprint,
            KEY_PRIVATE_KEY: self.private,
            KEY_VALIDATION_KEY: str(self.validation),
            KEY_LAST_AUDITED_AT_KEY: last_audited_at,
            KEY_ENCR_USED_KEY: self.encr_used,
            KEY_SIGN_USED_KEY: self.sign_used,
            KEY_VERSION_KEY: KEYMANAGER_DOC_VERSION,
            KEY_TAGS_KEY: [KEYMANAGER_ACTIVE_TAG],
        })

    def next(self):
        if self._index == 0:
            self._index = len(self.__slots__)
            raise StopIteration

        self._index -= 1
        key = self.__slots__[self._index]

        if key.startswith('_'):
            return self.next()

        value = getattr(self, key)
        if key == "validation":
            value = str(value)
        elif key in ["expiry_date", "last_audited_at", "refreshed_at"]:
            value = str(value)
        return key, value

    def __iter__(self):
        return self

    def __repr__(self):
        """
        Representation of this class
        """
        return u"<%s 0x%s (%s - %s)>" % (
            self.__class__.__name__,
            self.fingerprint,
            self.address,
            "priv" if self.private else "publ")


def init_indexes(soledad):
    """
    Initialize the database indexes.
    """
    leap_assert(soledad is not None,
                "Cannot init indexes with null soledad")

    def create_idexes(indexes):
        deferreds = []
        db_indexes = dict(indexes)
        # Loop through the indexes we expect to find.
        for name, expression in INDEXES.items():
            if name not in db_indexes:
                # The index does not yet exist.
                d = soledad.create_index(name, *expression)
                deferreds.append(d)
            elif expression != db_indexes[name]:
                # The index exists but the definition is not what expected,
                # so we delete it and add the proper index expression.
                d = soledad.delete_index(name)
                d.addCallback(
                    lambda _:
                        soledad.create_index(name, *expression))
                deferreds.append(d)
        return defer.gatherResults(deferreds, consumeErrors=True)

    d = soledad.list_indexes()
    d.addCallback(create_idexes)
    return d
