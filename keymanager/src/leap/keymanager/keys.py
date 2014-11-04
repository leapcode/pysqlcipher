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


from abc import ABCMeta, abstractmethod
from datetime import datetime
from leap.common.check import leap_assert

from leap.keymanager.validation import ValidationLevel, toValidationLevel

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
KEY_FIRST_SEEN_AT_KEY = 'first_seen_at'
KEY_LAST_AUDITED_AT_KEY = 'last_audited_at'
KEY_VALIDATION_KEY = 'validation'
KEY_TAGS_KEY = 'tags'


#
# Key storage constants
#

KEYMANAGER_KEY_TAG = 'keymanager-key'


#
# key indexing constants.
#

TAGS_PRIVATE_INDEX = 'by-tags-private'
TAGS_ADDRESS_PRIVATE_INDEX = 'by-tags-address-private'
INDEXES = {
    TAGS_PRIVATE_INDEX: [
        KEY_TAGS_KEY,
        'bool(%s)' % KEY_PRIVATE_KEY,
    ],
    TAGS_ADDRESS_PRIVATE_INDEX: [
        KEY_TAGS_KEY,
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


def build_key_from_dict(kClass, address, kdict):
    """
    Build an C{kClass} key bound to C{address} based on info in C{kdict}.

    :param address: The address bound to the key.
    :type address: str
    :param kdict: Dictionary with key data.
    :type kdict: dict
    :return: An instance of the key.
    :rtype: C{kClass}
    """
    leap_assert(
        address == kdict[KEY_ADDRESS_KEY],
        'Wrong address in key data.')
    try:
        validation = toValidationLevel(kdict[KEY_VALIDATION_KEY])
    except ValueError:
        logger.error("Not valid validation level (%s) for key %s",
                     (kdict[KEY_VALIDATION_KEY], kdict[KEY_ID_KEY]))
        validation = ValidationLevel.Weak_Chain

    expiry_date = None
    if kdict[KEY_EXPIRY_DATE_KEY]:
        expiry_date = datetime.fromtimestamp(int(kdict[KEY_EXPIRY_DATE_KEY]))

    return kClass(
        address,
        key_id=kdict[KEY_ID_KEY],
        fingerprint=kdict[KEY_FINGERPRINT_KEY],
        key_data=kdict[KEY_DATA_KEY],
        private=kdict[KEY_PRIVATE_KEY],
        length=kdict[KEY_LENGTH_KEY],
        expiry_date=expiry_date,
        first_seen_at=kdict[KEY_FIRST_SEEN_AT_KEY],
        last_audited_at=kdict[KEY_LAST_AUDITED_AT_KEY],
        validation=validation,
    )


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

    def __init__(self, address, key_id=None, fingerprint=None,
                 key_data=None, private=None, length=None, expiry_date=None,
                 validation=None, first_seen_at=None, last_audited_at=None):
        self.address = address
        self.key_id = key_id
        self.fingerprint = fingerprint
        self.key_data = key_data
        self.private = private
        self.length = length
        self.expiry_date = expiry_date
        self.validation = validation
        self.first_seen_at = first_seen_at
        self.last_audited_at = last_audited_at

    def get_json(self):
        """
        Return a JSON string describing this key.

        :return: The JSON string describing this key.
        :rtype: str
        """
        expiry_str = ""
        if self.expiry_date is not None:
            expiry_str = self.expiry_date.strftime("%s")

        return json.dumps({
            KEY_ADDRESS_KEY: self.address,
            KEY_TYPE_KEY: str(self.__class__),
            KEY_ID_KEY: self.key_id,
            KEY_FINGERPRINT_KEY: self.fingerprint,
            KEY_DATA_KEY: self.key_data,
            KEY_PRIVATE_KEY: self.private,
            KEY_LENGTH_KEY: self.length,
            KEY_EXPIRY_DATE_KEY: expiry_str,
            KEY_VALIDATION_KEY: str(self.validation),
            KEY_FIRST_SEEN_AT_KEY: self.first_seen_at,
            KEY_LAST_AUDITED_AT_KEY: self.last_audited_at,
            KEY_TAGS_KEY: [KEYMANAGER_KEY_TAG],
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
        # Ask the database for currently existing indexes.
        db_indexes = dict(self._soledad.list_indexes())
        # Loop through the indexes we expect to find.
        for name, expression in INDEXES.items():
            if name not in db_indexes:
                # The index does not yet exist.
                self._soledad.create_index(name, *expression)
                continue
            if expression == db_indexes[name]:
                # The index exists and is up to date.
                continue
            # The index exists but the definition is not what expected, so we
            # delete it and add the proper index expression.
            self._soledad.delete_index(name)
            self._soledad.create_index(name, *expression)

    @abstractmethod
    def get_key(self, address, private=False):
        """
        Get key from local storage.

        :param address: The address bound to the key.
        :type address: str
        :param private: Look for a private key instead of a public one?
        :type private: bool

        :return: The key bound to C{address}.
        :rtype: EncryptionKey
        @raise KeyNotFound: If the key was not found on local storage.
        """
        pass

    @abstractmethod
    def put_key(self, key):
        """
        Put a key in local storage.

        :param key: The key to be stored.
        :type key: EncryptionKey
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

        :return: The decrypted data.
        :rtype: str

        @raise InvalidSignature: Raised if unable to verify the signature with
            C{verify} key.
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

        :return: The signed data.
        :rtype: str
        """
        pass
