# -*- coding: utf-8 -*-
# openpgp.py
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
Infrastructure for using OpenPGP keys in Key Manager.
"""


import locale
import logging
import os
import re
import shutil
import sys
import tempfile

from contextlib import closing

from gnupg import GPG
from gnupg.gnupg import GPGUtilities
from gnupg._util import _make_binary_stream

from leap.common.check import leap_assert, leap_assert_type, leap_check
from leap.keymanager import errors
from leap.keymanager.keys import (
    EncryptionKey,
    EncryptionScheme,
    is_address,
    build_key_from_dict,
    KEYMANAGER_KEY_TAG,
    TAGS_ADDRESS_PRIVATE_INDEX,
)


logger = logging.getLogger(__name__)


#
# A temporary GPG keyring wrapped to provide OpenPGP functionality.
#

class TempGPGWrapper(object):
    """
    A context manager that wraps a temporary GPG keyring which only contains
    the keys given at object creation.
    """

    def __init__(self, keys=None, gpgbinary=None):
        """
        Create an empty temporary keyring and import any given C{keys} into
        it.

        :param keys: OpenPGP key, or list of.
        :type keys: OpenPGPKey or list of OpenPGPKeys
        :param gpgbinary: Name for GnuPG binary executable.
        :type gpgbinary: C{str}
        """
        self._gpg = None
        self._gpgbinary = gpgbinary
        if not keys:
            keys = list()
        if not isinstance(keys, list):
            keys = [keys]
        self._keys = keys
        for key in keys:
            leap_assert_type(key, OpenPGPKey)

    def __enter__(self):
        """
        Build and return a GPG keyring containing the keys given on
        object creation.

        :return: A GPG instance containing the keys given on object creation.
        :rtype: gnupg.GPG
        """
        self._build_keyring()
        return self._gpg

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Ensure the gpg is properly destroyed.
        """
        # TODO handle exceptions and log here
        self._destroy_keyring()

    def _build_keyring(self):
        """
        Create a GPG keyring containing the keys given on object creation.

        :return: A GPG instance containing the keys given on object creation.
        :rtype: gnupg.GPG
        """
        privkeys = [key for key in self._keys if key and key.private is True]
        publkeys = [key for key in self._keys if key and key.private is False]
        # here we filter out public keys that have a correspondent
        # private key in the list because the private key_data by
        # itself is enough to also have the public key in the keyring,
        # and we want to count the keys afterwards.

        privaddrs = map(lambda privkey: privkey.address, privkeys)
        publkeys = filter(
            lambda pubkey: pubkey.address not in privaddrs, publkeys)

        listkeys = lambda: self._gpg.list_keys()
        listsecretkeys = lambda: self._gpg.list_keys(secret=True)

        self._gpg = GPG(binary=self._gpgbinary,
                        homedir=tempfile.mkdtemp())
        leap_assert(len(listkeys()) is 0, 'Keyring not empty.')

        # import keys into the keyring:
        # concatenating ascii-armored keys, which is correctly
        # understood by GPG.

        self._gpg.import_keys("".join(
            [x.key_data for x in publkeys + privkeys]))

        # assert the number of keys in the keyring
        leap_assert(
            len(listkeys()) == len(publkeys) + len(privkeys),
            'Wrong number of public keys in keyring: %d, should be %d)' %
            (len(listkeys()), len(publkeys) + len(privkeys)))
        leap_assert(
            len(listsecretkeys()) == len(privkeys),
            'Wrong number of private keys in keyring: %d, should be %d)' %
            (len(listsecretkeys()), len(privkeys)))

    def _destroy_keyring(self):
        """
        Securely erase the keyring.
        """
        # TODO: implement some kind of wiping of data or a more
        # secure way that
        # does not write to disk.

        try:
            for secret in [True, False]:
                for key in self._gpg.list_keys(secret=secret):
                    self._gpg.delete_keys(
                        key['fingerprint'],
                        secret=secret)
            leap_assert(len(self._gpg.list_keys()) is 0, 'Keyring not empty!')

        except:
            raise

        finally:
            leap_assert(self._gpg.homedir != os.path.expanduser('~/.gnupg'),
                        "watch out! Tried to remove default gnupg home!")
            shutil.rmtree(self._gpg.homedir)


def _build_key_from_gpg(address, key, key_data):
    """
    Build an OpenPGPKey for C{address} based on C{key} from
    local gpg storage.

    ASCII armored GPG key data has to be queried independently in this
    wrapper, so we receive it in C{key_data}.

    :param address: The address bound to the key.
    :type address: str
    :param key: Key obtained from GPG storage.
    :type key: dict
    :param key_data: Key data obtained from GPG storage.
    :type key_data: str
    :return: An instance of the key.
    :rtype: OpenPGPKey
    """
    return OpenPGPKey(
        address,
        key_id=key['keyid'],
        fingerprint=key['fingerprint'],
        key_data=key_data,
        private=True if key['type'] == 'sec' else False,
        length=key['length'],
        expiry_date=key['expires'],
        validation=None,  # TODO: verify for validation.
    )


#
# The OpenPGP wrapper
#

class OpenPGPKey(EncryptionKey):
    """
    Base class for OpenPGP keys.
    """


class OpenPGPScheme(EncryptionScheme):
    """
    A wrapper for OpenPGP keys management and use (encryption, decyption,
    signing and verification).
    """

    def __init__(self, soledad, gpgbinary=None):
        """
        Initialize the OpenPGP wrapper.

        :param soledad: A Soledad instance for key storage.
        :type soledad: leap.soledad.Soledad
        :param gpgbinary: Name for GnuPG binary executable.
        :type gpgbinary: C{str}
        """
        EncryptionScheme.__init__(self, soledad)
        self._gpgbinary = gpgbinary

    #
    # Keys management
    #

    def gen_key(self, address):
        """
        Generate an OpenPGP keypair bound to C{address}.

        :param address: The address bound to the key.
        :type address: str
        :return: The key bound to C{address}.
        :rtype: OpenPGPKey
        @raise KeyAlreadyExists: If key already exists in local database.
        """
        # make sure the key does not already exist
        leap_assert(is_address(address), 'Not an user address: %s' % address)
        try:
            self.get_key(address)
            raise errors.KeyAlreadyExists(address)
        except errors.KeyNotFound:
            logger.debug('Key for %s not found' % (address,))

        with self._temporary_gpgwrapper() as gpg:
            # TODO: inspect result, or use decorator
            params = gpg.gen_key_input(
                key_type='RSA',
                key_length=4096,
                name_real=address,
                name_email=address,
                name_comment='')
            logger.info("About to generate keys... This might take SOME time.")
            gpg.gen_key(params)
            logger.info("Keys for %s have been successfully "
                        "generated." % (address,))
            pubkeys = gpg.list_keys()

            # assert for new key characteristics

            # XXX This exception is not properly catched by the soledad
            # bootstrapping, so if we do not finish generating the keys
            # we end with a blocked thread -- kali

            leap_assert(
                len(pubkeys) is 1,  # a unitary keyring!
                'Keyring has wrong number of keys: %d.' % len(pubkeys))
            key = gpg.list_keys(secret=True).pop()
            leap_assert(
                len(key['uids']) is 1,  # with just one uid!
                'Wrong number of uids for key: %d.' % len(key['uids']))
            leap_assert(
                re.match('.*<%s>$' % address, key['uids'][0]) is not None,
                'Key not correctly bound to address.')
            # insert both public and private keys in storage
            for secret in [True, False]:
                key = gpg.list_keys(secret=secret).pop()
                openpgp_key = _build_key_from_gpg(
                    address, key,
                    gpg.export_keys(key['fingerprint'], secret=secret))
                self.put_key(openpgp_key)

        return self.get_key(address, private=True)

    def get_key(self, address, private=False):
        """
        Get key bound to C{address} from local storage.

        :param address: The address bound to the key.
        :type address: str
        :param private: Look for a private key instead of a public one?
        :type private: bool

        :return: The key bound to C{address}.
        :rtype: OpenPGPKey
        @raise KeyNotFound: If the key was not found on local storage.
        """
        leap_assert(is_address(address), 'Not an user address: %s' % address)
        doc = self._get_key_doc(address, private)
        if doc is None:
            raise errors.KeyNotFound(address)
        return build_key_from_dict(OpenPGPKey, address, doc.content)

    def parse_ascii_key(self, key_data):
        """
        Parses an ascii armored key (or key pair) data and returns
        the OpenPGPKey keys.

        :param key_data: the key data to be parsed.
        :type key_data: str or unicode

        :returns: the public key and private key (if applies) for that data.
        :rtype: (public, private) -> tuple(OpenPGPKey, OpenPGPKey)
                the tuple may have one or both components None
        """
        leap_assert_type(key_data, (str, unicode))
        # TODO: add more checks for correct key data.
        leap_assert(key_data is not None, 'Data does not represent a key.')
        mail_regex = '.*<([\w.-]+@[\w.-]+)>.*'

        with self._temporary_gpgwrapper() as gpg:
            # TODO: inspect result, or use decorator
            gpg.import_keys(key_data)
            privkey = None
            pubkey = None

            try:
                privkey = gpg.list_keys(secret=True).pop()
            except IndexError:
                pass
            pubkey = gpg.list_keys(secret=False).pop()  # unitary keyring

            # extract adress from first uid on key
            match = re.match(mail_regex, pubkey['uids'].pop())
            leap_assert(match is not None, 'No user address in key data.')
            address = match.group(1)

            if privkey is not None:
                match = re.match(mail_regex, privkey['uids'].pop())
                leap_assert(match is not None, 'No user address in key data.')
                privaddress = match.group(1)

                # build private key
                openpgp_privkey = _build_key_from_gpg(
                    privaddress, privkey,
                    gpg.export_keys(privkey['fingerprint'], secret=True))

                leap_check(address == privaddress,
                           'Addresses in public and private key differ.',
                           errors.KeyAddressMismatch)
                leap_check(pubkey['fingerprint'] == privkey['fingerprint'],
                           'Fingerprints for public and private key differ.',
                           errors.KeyFingerprintMismatch)

            # build public key
            openpgp_pubkey = _build_key_from_gpg(
                address, pubkey,
                gpg.export_keys(pubkey['fingerprint'], secret=False))

            return (openpgp_pubkey, openpgp_privkey)

    def put_ascii_key(self, key_data):
        """
        Put key contained in ascii-armored C{key_data} in local storage.

        :param key_data: The key data to be stored.
        :type key_data: str or unicode
        """
        leap_assert_type(key_data, (str, unicode))

        try:
            openpgp_pubkey, openpgp_privkey = self.parse_ascii_key(key_data)
        except (errors.KeyAddressMismatch, errors.KeyFingerprintMismatch) as e:
            leap_assert(False, repr(e))

        if openpgp_pubkey is not None:
            self.put_key(openpgp_pubkey)
        if openpgp_privkey is not None:
            self.put_key(openpgp_privkey)

    def put_key(self, key):
        """
        Put C{key} in local storage.

        :param key: The key to be stored.
        :type key: OpenPGPKey
        """
        doc = self._get_key_doc(key.address, private=key.private)
        if doc is None:
            self._soledad.create_doc_from_json(key.get_json())
        else:
            doc.set_json(key.get_json())
            self._soledad.put_doc(doc)

    def _get_key_doc(self, address, private=False):
        """
        Get the document with a key (public, by default) bound to C{address}.

        If C{private} is True, looks for a private key instead of a public.

        :param address: The address bound to the key.
        :type address: str
        :param private: Whether to look for a private key.
        :type private: bool
        :return: The document with the key or None if it does not exist.
        :rtype: leap.soledad.document.SoledadDocument
        """
        doclist = self._soledad.get_from_index(
            TAGS_ADDRESS_PRIVATE_INDEX,
            KEYMANAGER_KEY_TAG,
            address,
            '1' if private else '0')
        if len(doclist) is 0:
            return None
        leap_assert(
            len(doclist) is 1,
            'Found more than one %s key for address!' %
            'private' if private else 'public')
        return doclist.pop()

    def delete_key(self, key):
        """
        Remove C{key} from storage.

        May raise:
            errors.KeyNotFound
            errors.KeyAttributesDiffer

        :param key: The key to be removed.
        :type key: EncryptionKey
        """
        leap_assert_type(key, OpenPGPKey)
        stored_key = self.get_key(key.address, private=key.private)
        if stored_key is None:
            raise errors.KeyNotFound(key)
        if stored_key.__dict__ != key.__dict__:
            raise errors.KeyAttributesDiffer(key)
        doc = self._get_key_doc(key.address, key.private)
        self._soledad.delete_doc(doc)

    #
    # Data encryption, decryption, signing and verifying
    #

    def _temporary_gpgwrapper(self, keys=None):
        """
        Return a gpg wrapper that implements the context manager protocol and
        contains C{keys}.

        :param key_data: ASCII armored key data.
        :type key_data: str
        :param gpgbinary: Name for GnuPG binary executable.
        :type gpgbinary: C{str}

        :return: a TempGPGWrapper instance
        :rtype: TempGPGWrapper
        """
        # TODO do here checks on key_data
        return TempGPGWrapper(
            keys=keys, gpgbinary=self._gpgbinary)

    @staticmethod
    def _assert_gpg_result_ok(result):
        """
        Check if GPG result is 'ok' and log stderr outputs.
        :param result: The GPG results
        :type result:
        """
        stderr = getattr(result, 'stderr', None)
        if stderr:
            logger.debug("%s" % (stderr,))
        if getattr(result, 'ok', None) is not True:
            raise errors.EncryptionDecryptionFailed(
                'Failed to encrypt/decrypt: %s' % stderr)

    def encrypt(self, data, pubkey, passphrase=None, sign=None,
                cipher_algo='AES256'):
        """
        Encrypt C{data} using public @{pubkey} and sign with C{sign} key.

        :param data: The data to be encrypted.
        :type data: str
        :param pubkey: The key used to encrypt.
        :type pubkey: OpenPGPKey
        :param sign: The key used for signing.
        :type sign: OpenPGPKey
        :param cipher_algo: The cipher algorithm to use.
        :type cipher_algo: str

        :return: The encrypted data.
        :rtype: str
        """
        leap_assert_type(pubkey, OpenPGPKey)
        leap_assert(pubkey.private is False, 'Key is not public.')
        keys = [pubkey]
        if sign is not None:
            leap_assert_type(sign, OpenPGPKey)
            leap_assert(sign.private is True)
            keys.append(sign)
        with self._temporary_gpgwrapper(keys) as gpg:
            result = gpg.encrypt(
                data, pubkey.fingerprint,
                default_key=sign.key_id if sign else None,
                passphrase=passphrase, symmetric=False,
                cipher_algo=cipher_algo)
            # Here we cannot assert for correctness of sig because the sig is
            # in the ciphertext.
            # result.ok    - (bool) indicates if the operation succeeded
            # result.data  - (bool) contains the result of the operation
            self._assert_gpg_result_ok(result)
            return result.data

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
        :rtype: unicode

        @raise InvalidSignature: Raised if unable to verify the signature with
            C{verify} key.
        """
        leap_assert(privkey.private is True, 'Key is not private.')
        keys = [privkey]
        if verify is not None:
            leap_assert_type(verify, OpenPGPKey)
            leap_assert(verify.private is False)
            keys.append(verify)
        with self._temporary_gpgwrapper(keys) as gpg:
            result = gpg.decrypt(
                data, passphrase=passphrase, always_trust=True)
            self._assert_gpg_result_ok(result)
            # verify signature
            if (verify is not None):
                if result.valid is False or \
                        verify.fingerprint != result.pubkey_fingerprint:
                    raise errors.InvalidSignature(
                        'Failed to verify signature with key %s: %s' %
                        (verify.key_id, stderr))

            # XXX: this is the encoding used by gpg module
            # https://github.com/isislovecruft/python-gnupg/\
            #   blob/master/gnupg/_meta.py#L121
            encoding = locale.getpreferredencoding()
            if encoding is None:
                encoding = sys.stdin.encoding
            if encoding is None:
                encoding = 'utf-8'
            return result.data.decode(encoding, 'replace')

    def is_encrypted(self, data):
        """
        Return whether C{data} was asymmetrically encrypted using OpenPGP.

        :param data: The data we want to know about.
        :type data: str

        :return: Whether C{data} was encrypted using this wrapper.
        :rtype: bool
        """
        with self._temporary_gpgwrapper() as gpg:
            gpgutil = GPGUtilities(gpg)
            return gpgutil.is_encrypted_asym(data)

    def sign(self, data, privkey, digest_algo='SHA512', clearsign=False,
             detach=True, binary=False):
        """
        Sign C{data} with C{privkey}.

        :param data: The data to be signed.
        :type data: str

        :param privkey: The private key to be used to sign.
        :type privkey: OpenPGPKey
        :param digest_algo: The hash digest to use.
        :type digest_algo: str
        :param clearsign: If True, create a cleartext signature.
        :type clearsign: bool
        :param detach: If True, create a detached signature.
        :type detach: bool
        :param binary: If True, do not ascii armour the output.
        :type binary: bool

        :return: The ascii-armored signed data.
        :rtype: str
        """
        leap_assert_type(privkey, OpenPGPKey)
        leap_assert(privkey.private is True)

        # result.fingerprint - contains the fingerprint of the key used to
        #                      sign.
        with self._temporary_gpgwrapper(privkey) as gpg:
            result = gpg.sign(data, default_key=privkey.key_id,
                              digest_algo=digest_algo, clearsign=clearsign,
                              detach=detach, binary=binary)
            rfprint = privkey.fingerprint
            privkey = gpg.list_keys(secret=True).pop()
            kfprint = privkey['fingerprint']
            if result.fingerprint is None:
                raise errors.SignFailed(
                    'Failed to sign with key %s: %s' %
                    (privkey['keyid'], stderr))
            leap_assert(
                result.fingerprint == kfprint,
                'Signature and private key fingerprints mismatch: '
                '%s != %s' % (rfprint, kfprint))
        return result.data

    def verify(self, data, pubkey, detached_sig=None):
        """
        Verify signed C{data} with C{pubkey}, eventually using
        C{detached_sig}.

        :param data: The data to be verified.
        :type data: str
        :param pubkey: The public key to be used on verification.
        :type pubkey: OpenPGPKey
        :param detached_sig: A detached signature. If given, C{data} is
                             verified against this detached signature.
        :type detached_sig: str

        :return: The ascii-armored signed data.
        :rtype: str
        """
        leap_assert_type(pubkey, OpenPGPKey)
        leap_assert(pubkey.private is False)
        with self._temporary_gpgwrapper(pubkey) as gpg:
            result = None
            if detached_sig is None:
                result = gpg.verify(data)
            else:
                # to verify using a detached sig we have to use
                # gpg.verify_file(), which receives the data as a binary
                # stream and the name of a file containing the signature.
                sf, sfname = tempfile.mkstemp()
                with os.fdopen(sf, 'w') as sfd:
                    sfd.write(detached_sig)
                with closing(_make_binary_stream(data, gpg._encoding)) as df:
                    result = gpg.verify_file(df, sig_file=sfname)
            gpgpubkey = gpg.list_keys().pop()
            valid = result.valid
            rfprint = result.fingerprint
            kfprint = gpgpubkey['fingerprint']
            # raise in case sig is invalid
            if valid is False or rfprint != kfprint:
                raise errors.InvalidSignature(
                    'Failed to verify signature '
                    'with key %s.' % gpgpubkey['keyid'])
            return True
