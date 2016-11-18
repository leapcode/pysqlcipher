# -*- coding: utf-8 -*-
# keys.py
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
Abstact key type and encryption scheme representations.
"""
import json
import re
import time

from datetime import datetime

from twisted.logger import Logger

from leap.bitmask.keymanager import errors
from leap.bitmask.keymanager.wrapper import TempGPGWrapper
from leap.bitmask.keymanager.validation import ValidationLevels
from leap.bitmask.keymanager import documents as doc

logger = Logger()


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


def build_key_from_dict(key, active=None):
    """
    Build an OpenPGPKey key based on info in C{kdict}.

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
        address = active[doc.KEY_ADDRESS_KEY]
        try:
            validation = ValidationLevels.get(active[doc.KEY_VALIDATION_KEY])
        except ValueError:
            logger.error("Not valid validation level (%s) for key %s",
                         (active[doc.KEY_VALIDATION_KEY],
                          active[doc.KEY_FINGERPRINT_KEY]))
        last_audited_at = _to_datetime(active[doc.KEY_LAST_AUDITED_AT_KEY])
        encr_used = active[doc.KEY_ENCR_USED_KEY]
        sign_used = active[doc.KEY_SIGN_USED_KEY]

    expiry_date = _to_datetime(key[doc.KEY_EXPIRY_DATE_KEY])
    refreshed_at = _to_datetime(key[doc.KEY_REFRESHED_AT_KEY])

    return OpenPGPKey(
        address=address,
        uids=key[doc.KEY_UIDS_KEY],
        fingerprint=key[doc.KEY_FINGERPRINT_KEY],
        key_data=key[doc.KEY_DATA_KEY],
        private=key[doc.KEY_PRIVATE_KEY],
        length=key[doc.KEY_LENGTH_KEY],
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


class OpenPGPKey(object):
    """
    Base class for OpenPGP keys.
    """

    __slots__ = ('address', 'uids', 'fingerprint', 'key_data',
                 'private', 'length', 'expiry_date', 'validation',
                 'last_audited_at', 'refreshed_at',
                 'encr_used', 'sign_used', '_index', '_gpgbinary')

    def __init__(self, address=None, gpgbinary=None, uids=[], fingerprint="",
                 key_data="", private=False, length=0, expiry_date=None,
                 validation=ValidationLevels.Weak_Chain, last_audited_at=None,
                 refreshed_at=None, encr_used=False, sign_used=False):
        self._gpgbinary = gpgbinary
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

    @property
    def signatures(self):
        """
        Get the key signatures

        :return: the key IDs that have signed the key
        :rtype: list(str)
        """
        with TempGPGWrapper(keys=[self], gpgbinary=self._gpgbinary) as gpg:
            res = gpg.list_sigs(self.fingerprint)
            for uid, sigs in res.sigs.iteritems():
                if parse_address(uid) in self.uids:
                    return sigs

        return []

    def merge(self, newkey):
        if newkey.fingerprint != self.fingerprint:
            logger.critical(
                "Can't put a key whith the same key_id and different "
                "fingerprint: %s, %s"
                % (newkey.fingerprint, self.fingerprint))
            raise errors.KeyFingerprintMismatch(newkey.fingerprint)

        with TempGPGWrapper(gpgbinary=self._gpgbinary) as gpg:
            gpg.import_keys(self.key_data)
            gpg.import_keys(newkey.key_data)
            gpgkey = gpg.list_keys(secret=newkey.private).pop()

            if gpgkey['expires']:
                self.expiry_date = datetime.fromtimestamp(
                    int(gpgkey['expires']))
            else:
                self.expiry_date = None

            self.uids = []
            for uid in gpgkey['uids']:
                self.uids.append(parse_address(uid))

            self.length = int(gpgkey['length'])
            self.key_data = gpg.export_keys(gpgkey['fingerprint'],
                                            secret=self.private)

        if newkey.validation > self.validation:
            self.validation = newkey.validation
        if newkey.last_audited_at > self.last_audited_at:
            self.validation = newkey.last_audited_at
        self.encr_used = newkey.encr_used or self.encr_used
        self.sign_used = newkey.sign_used or self.sign_used
        self.refreshed_at = datetime.now()

    def get_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        expiry_date = _to_unix_time(self.expiry_date)
        refreshed_at = _to_unix_time(self.refreshed_at)

        return json.dumps({
            doc.KEY_UIDS_KEY: self.uids,
            doc.KEY_TYPE_KEY: self.__class__.__name__,
            doc.KEY_FINGERPRINT_KEY: self.fingerprint,
            doc.KEY_DATA_KEY: self.key_data,
            doc.KEY_PRIVATE_KEY: self.private,
            doc.KEY_LENGTH_KEY: self.length,
            doc.KEY_EXPIRY_DATE_KEY: expiry_date,
            doc.KEY_REFRESHED_AT_KEY: refreshed_at,
            doc.KEY_VERSION_KEY: doc.KEYMANAGER_DOC_VERSION,
            doc.KEY_TAGS_KEY: [doc.KEYMANAGER_KEY_TAG],
        })

    def get_active_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        last_audited_at = _to_unix_time(self.last_audited_at)

        return json.dumps({
            doc.KEY_ADDRESS_KEY: self.address,
            doc.KEY_TYPE_KEY: (self.__class__.__name__ +
                               doc.KEYMANAGER_ACTIVE_TYPE),
            doc.KEY_FINGERPRINT_KEY: self.fingerprint,
            doc.KEY_PRIVATE_KEY: self.private,
            doc.KEY_VALIDATION_KEY: str(self.validation),
            doc.KEY_LAST_AUDITED_AT_KEY: last_audited_at,
            doc.KEY_ENCR_USED_KEY: self.encr_used,
            doc.KEY_SIGN_USED_KEY: self.sign_used,
            doc.KEY_VERSION_KEY: doc.KEYMANAGER_DOC_VERSION,
            doc.KEY_TAGS_KEY: [doc.KEYMANAGER_ACTIVE_TAG],
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

    def is_active(self):
        """
        Indicates if a key is active.
        :return: True if key is active.
        :rtype: bool
        """
        return True if self.address is not None else False

    def set_unactive(self):
        """
        Sets a key as unactive.
        """
        self.address = None

    def is_expired(self):
        """
        Indicates if a key is expired.
        :return: True if key expired.
        :rtype: bool
        """
        return False if self.expiry_date is None \
            else self.expiry_date < datetime.now()


def parse_address(address):
    """
    Remove name, '<', '>' and the identity suffix after the '+' until the '@'
    e.g.: test_user+something@provider.com becomes test_user@provider.com
    since the key belongs to the identity without the '+' suffix.

    :type address: str
    :rtype: str
    """
    mail_regex = '(.*<)?([\w.-]+)(\+.*)?(@[\w.-]+)(>.*)?'
    match = re.match(mail_regex, address)
    if match is None:
        return None
    return ''.join(match.group(2, 4))
