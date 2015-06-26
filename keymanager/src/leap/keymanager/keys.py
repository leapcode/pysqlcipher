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


from abc import ABCMeta, abstractmethod
from datetime import datetime
from leap.common.check import leap_assert
from twisted.internet import defer

from leap.keymanager.validation import ValidationLevels

logger = logging.getLogger(__name__)


#
# Dictionary keys used for storing cryptographic keys.
#

KEY_ADDRESS_KEY = 'address'
KEY_TYPE_KEY = 'type'
KEY_ID_KEY = 'key_id'
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


#
# key indexing constants.
#

TAGS_PRIVATE_INDEX = 'by-tags-private'
TYPE_ID_PRIVATE_INDEX = 'by-type-id-private'
TYPE_ADDRESS_PRIVATE_INDEX = 'by-type-address-private'
INDEXES = {
    TAGS_PRIVATE_INDEX: [
        KEY_TAGS_KEY,
        'bool(%s)' % KEY_PRIVATE_KEY,
    ],
    TYPE_ID_PRIVATE_INDEX: [
        KEY_TYPE_KEY,
        KEY_ID_KEY,
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


def build_key_from_dict(kClass, kdict):
    """
    Build an C{kClass} key based on info in C{kdict}.

    :param kdict: Dictionary with key data.
    :type kdict: dict
    :return: An instance of the key.
    :rtype: C{kClass}
    """
    try:
        validation = ValidationLevels.get(kdict[KEY_VALIDATION_KEY])
    except ValueError:
        logger.error("Not valid validation level (%s) for key %s",
                     (kdict[KEY_VALIDATION_KEY], kdict[KEY_ID_KEY]))
        validation = ValidationLevels.Weak_Chain

    expiry_date = _to_datetime(kdict[KEY_EXPIRY_DATE_KEY])
    last_audited_at = _to_datetime(kdict[KEY_LAST_AUDITED_AT_KEY])
    refreshed_at = _to_datetime(kdict[KEY_REFRESHED_AT_KEY])

    return kClass(
        kdict[KEY_ADDRESS_KEY],
        key_id=kdict[KEY_ID_KEY],
        fingerprint=kdict[KEY_FINGERPRINT_KEY],
        key_data=kdict[KEY_DATA_KEY],
        private=kdict[KEY_PRIVATE_KEY],
        length=kdict[KEY_LENGTH_KEY],
        expiry_date=expiry_date,
        last_audited_at=last_audited_at,
        refreshed_at=refreshed_at,
        validation=validation,
        encr_used=kdict[KEY_ENCR_USED_KEY],
        sign_used=kdict[KEY_SIGN_USED_KEY],
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

    def __init__(self, address, key_id="", fingerprint="",
                 key_data="", private=False, length=0, expiry_date=None,
                 validation=ValidationLevels.Weak_Chain, last_audited_at=None,
                 refreshed_at=None, encr_used=False, sign_used=False):
        self.address = address
        self.key_id = key_id
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

    def get_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        expiry_date = _to_unix_time(self.expiry_date)
        last_audited_at = _to_unix_time(self.last_audited_at)
        refreshed_at = _to_unix_time(self.refreshed_at)

        return json.dumps({
            KEY_ADDRESS_KEY: self.address,
            KEY_TYPE_KEY: self.__class__.__name__,
            KEY_ID_KEY: self.key_id,
            KEY_FINGERPRINT_KEY: self.fingerprint,
            KEY_DATA_KEY: self.key_data,
            KEY_PRIVATE_KEY: self.private,
            KEY_LENGTH_KEY: self.length,
            KEY_EXPIRY_DATE_KEY: expiry_date,
            KEY_LAST_AUDITED_AT_KEY: last_audited_at,
            KEY_REFRESHED_AT_KEY: refreshed_at,
            KEY_VALIDATION_KEY: str(self.validation),
            KEY_ENCR_USED_KEY: self.encr_used,
            KEY_SIGN_USED_KEY: self.sign_used,
            KEY_TAGS_KEY: [KEYMANAGER_KEY_TAG],
        })

    def get_active_json(self, address):
        """
        Return a JSON string describing this key.

        :param address: Address for wich the key is active
        :type address: str
        :return: The JSON string describing this key.
        :rtype: str
        """
        return json.dumps({
            KEY_ADDRESS_KEY: address,
            KEY_TYPE_KEY: self.__class__.__name__ + KEYMANAGER_ACTIVE_TYPE,
            KEY_ID_KEY: self.key_id,
            KEY_PRIVATE_KEY: self.private,
            KEY_TAGS_KEY: [KEYMANAGER_ACTIVE_TAG],
        })

    def __repr__(self):
        """
        Representation of this class
        """
        return u"<%s 0x%s (%s - %s)>" % (
            self.__class__.__name__,
            self.key_id,
            self.address,
            "priv" if self.private else "publ")


#
# Encryption schemes
#

class EncryptionScheme(object):
    """
    Abstract class for Encryption Schemes.

    A wrapper for a certain encryption schemes should know how to get and put
    keys in local storage using Soledad, how to generate new keys and how to
    find out about possibly encrypted content.
    """

    __metaclass__ = ABCMeta

    def __init__(self, soledad):
        """
        Initialize this Encryption Scheme.

        :param soledad: A Soledad instance for local storage of keys.
        :type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad
        self._init_indexes()

    def _init_indexes(self):
        """
        Initialize the database indexes.
        """
        leap_assert(self._soledad is not None,
                    "Cannot init indexes with null soledad")

        def init_idexes(indexes):
            deferreds = []
            db_indexes = dict(indexes)
            # Loop through the indexes we expect to find.
            for name, expression in INDEXES.items():
                if name not in db_indexes:
                    # The index does not yet exist.
                    d = self._soledad.create_index(name, *expression)
                    deferreds.append(d)
                elif expression != db_indexes[name]:
                    # The index exists but the definition is not what expected,
                    # so we delete it and add the proper index expression.
                    d = self._soledad.delete_index(name)
                    d.addCallback(
                        lambda _:
                            self._soledad.create_index(name, *expression))
                    deferreds.append(d)
            return defer.gatherResults(deferreds, consumeErrors=True)

        self.deferred_indexes = self._soledad.list_indexes()
        self.deferred_indexes.addCallback(init_idexes)

    def _wait_indexes(self, *methods):
        """
        Methods that need to wait for the indexes to be ready.

        Heavily based on
        http://blogs.fluidinfo.com/terry/2009/05/11/a-mixin-class-allowing-python-__init__-methods-to-work-with-twisted-deferreds/

        :param methods: methods that need to wait for the indexes to be ready
        :type methods: tuple(str)
        """
        self.waiting = []
        self.stored = {}

        def restore(_):
            for method in self.stored:
                setattr(self, method, self.stored[method])
            for d in self.waiting:
                d.callback(None)

        def makeWrapper(method):
            def wrapper(*args, **kw):
                d = defer.Deferred()
                d.addCallback(lambda _: self.stored[method](*args, **kw))
                self.waiting.append(d)
                return d
            return wrapper

        for method in methods:
            self.stored[method] = getattr(self, method)
            setattr(self, method, makeWrapper(method))

        self.deferred_indexes.addCallback(restore)

    @abstractmethod
    def get_key(self, address, private=False):
        """
        Get key from local storage.

        :param address: The address bound to the key.
        :type address: str
        :param private: Look for a private key instead of a public one?
        :type private: bool

        :return: A Deferred which fires with the EncryptionKey bound to
                 address, or which fails with KeyNotFound if the key was not
                 found on local storage.
        :rtype: Deferred
        """
        pass

    @abstractmethod
    def put_key(self, key, address):
        """
        Put a key in local storage.

        :param key: The key to be stored.
        :type key: EncryptionKey
        :param address: address for which this key will be active.
        :type address: str

        :return: A Deferred which fires when the key is in the storage.
        :rtype: Deferred
        """
        pass

    @abstractmethod
    def gen_key(self, address):
        """
        Generate a new key.

        :param address: The address bound to the key.
        :type address: str

        :return: The key bound to C{address}.
        :rtype: EncryptionKey
        """
        pass

    @abstractmethod
    def delete_key(self, key):
        """
        Remove C{key} from storage.

        :param key: The key to be removed.
        :type key: EncryptionKey

        :return: A Deferred which fires when the key is deleted, or which
                 fails with KeyNotFound if the key was not found on local
                 storage.
        :rtype: Deferred
        """
        pass

    @abstractmethod
    def encrypt(self, data, pubkey, passphrase=None, sign=None):
        """
        Encrypt C{data} using public @{pubkey} and sign with C{sign} key.

        :param data: The data to be encrypted.
        :type data: str
        :param pubkey: The key used to encrypt.
        :type pubkey: EncryptionKey
        :param sign: The key used for signing.
        :type sign: EncryptionKey

        :return: The encrypted data.
        :rtype: str
        """
        pass

    @abstractmethod
    def decrypt(self, data, privkey, passphrase=None, verify=None):
        """
        Decrypt C{data} using private @{privkey} and verify with C{verify} key.

        :param data: The data to be decrypted.
        :type data: str
        :param privkey: The key used to decrypt.
        :type privkey: OpenPGPKey
        :param verify: The key used to verify a signature.
        :type verify: OpenPGPKey

        :return: The decrypted data and if signature verifies
        :rtype: (unicode, bool)

        :raise DecryptError: Raised if failed decrypting for some reason.
        """
        pass

    @abstractmethod
    def sign(self, data, privkey):
        """
        Sign C{data} with C{privkey}.

        :param data: The data to be signed.
        :type data: str

        :param privkey: The private key to be used to sign.
        :type privkey: EncryptionKey

        :return: The signed data.
        :rtype: str
        """
        pass

    @abstractmethod
    def verify(self, data, pubkey, detached_sig=None):
        """
        Verify signed C{data} with C{pubkey}, eventually using
        C{detached_sig}.

        :param data: The data to be verified.
        :type data: str
        :param pubkey: The public key to be used on verification.
        :type pubkey: EncryptionKey
        :param detached_sig: A detached signature. If given, C{data} is
                             verified against this sdetached signature.
        :type detached_sig: str

        :return: signature matches
        :rtype: bool
        """
        pass
