# -*- coding: utf-8 -*-
# openpgp.py
# Copyright (C) 2013-2015 LEAP
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
import logging
import os
import re
import shutil
import tempfile
import traceback
import io


from datetime import datetime
from gnupg import GPG
from gnupg.gnupg import GPGUtilities
from twisted.internet import defer

from leap.common.check import leap_assert, leap_assert_type, leap_check
from leap.keymanager import errors
from leap.keymanager.keys import (
    EncryptionKey,
    EncryptionScheme,
    is_address,
    build_key_from_dict,
    TYPE_ID_PRIVATE_INDEX,
    TYPE_ADDRESS_PRIVATE_INDEX,
    KEY_ADDRESS_KEY,
    KEY_ID_KEY,
    KEY_FINGERPRINT_KEY,
    KEY_REFRESHED_AT_KEY,
    KEYMANAGER_ACTIVE_TYPE,
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

        privids = map(lambda privkey: privkey.key_id, privkeys)
        publkeys = filter(
            lambda pubkey: pubkey.key_id not in privids, publkeys)

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


def _parse_address(address):
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


#
# The OpenPGP wrapper
#

class OpenPGPKey(EncryptionKey):
    """
    Base class for OpenPGP keys.
    """

    def __init__(self, address, gpgbinary=None, **kwargs):
        self._gpgbinary = gpgbinary
        super(OpenPGPKey, self).__init__(address, **kwargs)

    @property
    def signatures(self):
        """
        Get the key signatures

        :return: the key IDs that have signed the key
        :rtype: list(str)
        """
        with TempGPGWrapper(keys=[self], gpgbinary=self._gpgbinary) as gpg:
            res = gpg.list_sigs(self.key_id)
            for uid, sigs in res.sigs.iteritems():
                if _parse_address(uid) in self.address:
                    return sigs

        return []


class OpenPGPScheme(EncryptionScheme):
    """
    A wrapper for OpenPGP keys management and use (encryption, decyption,
    signing and verification).
    """

    # type used on the soledad documents
    KEY_TYPE = OpenPGPKey.__name__
    ACTIVE_TYPE = KEY_TYPE + KEYMANAGER_ACTIVE_TYPE

    def __init__(self, soledad, gpgbinary=None):
        """
        Initialize the OpenPGP wrapper.

        :param soledad: A Soledad instance for key storage.
        :type soledad: leap.soledad.Soledad
        :param gpgbinary: Name for GnuPG binary executable.
        :type gpgbinary: C{str}
        """
        EncryptionScheme.__init__(self, soledad)
        self._wait_indexes("get_key", "put_key")
        self._gpgbinary = gpgbinary

    #
    # Keys management
    #

    def gen_key(self, address):
        """
        Generate an OpenPGP keypair bound to C{address}.

        :param address: The address bound to the key.
        :type address: str

        :return: A Deferred which fires with the key bound to address, or fails
                 with KeyAlreadyExists if key already exists in local database.
        :rtype: Deferred
        """
        # make sure the key does not already exist
        leap_assert(is_address(address), 'Not an user address: %s' % address)

        def _gen_key(_):
            with TempGPGWrapper(gpgbinary=self._gpgbinary) as gpg:
                # TODO: inspect result, or use decorator
                params = gpg.gen_key_input(
                    key_type='RSA',
                    key_length=4096,
                    name_real=address,
                    name_email=address,
                    name_comment='')
                logger.info("About to generate keys... "
                            "This might take SOME time.")
                gpg.gen_key(params)
                logger.info("Keys for %s have been successfully "
                            "generated." % (address,))
                pubkeys = gpg.list_keys()

                # assert for new key characteristics
                leap_assert(
                    len(pubkeys) is 1,  # a unitary keyring!
                    'Keyring has wrong number of keys: %d.' % len(pubkeys))
                key = gpg.list_keys(secret=True).pop()
                leap_assert(
                    len(key['uids']) is 1,  # with just one uid!
                    'Wrong number of uids for key: %d.' % len(key['uids']))
                uid_match = False
                for uid in key['uids']:
                    if re.match('.*<%s>$' % address, uid) is not None:
                        uid_match = True
                        break
                leap_assert(uid_match, 'Key not correctly bound to address.')

                # insert both public and private keys in storage
                deferreds = []
                for secret in [True, False]:
                    key = gpg.list_keys(secret=secret).pop()
                    openpgp_key = self._build_key_from_gpg(
                        key,
                        gpg.export_keys(key['fingerprint'], secret=secret))
                    d = self.put_key(openpgp_key, address)
                    deferreds.append(d)
                return defer.gatherResults(deferreds)

        def key_already_exists(_):
            raise errors.KeyAlreadyExists(address)

        d = self.get_key(address)
        d.addCallbacks(key_already_exists, _gen_key)
        d.addCallback(lambda _: self.get_key(address, private=True))
        return d

    def get_key(self, address, private=False):
        """
        Get key bound to C{address} from local storage.

        :param address: The address bound to the key.
        :type address: str
        :param private: Look for a private key instead of a public one?
        :type private: bool

        :return: A Deferred which fires with the OpenPGPKey bound to address,
                 or which fails with KeyNotFound if the key was not found on
                 local storage.
        :rtype: Deferred
        """
        address = _parse_address(address)

        def build_key(doc):
            if doc is None:
                raise errors.KeyNotFound(address)
            leap_assert(
                address in doc.content[KEY_ADDRESS_KEY],
                'Wrong address in key %s. Expected %s, found %s.'
                % (doc.content[KEY_ID_KEY], address,
                   doc.content[KEY_ADDRESS_KEY]))
            key = build_key_from_dict(OpenPGPKey, doc.content)
            key._gpgbinary = self._gpgbinary
            return key

        d = self._get_key_doc(address, private)
        d.addCallback(build_key)
        return d

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

        priv_info, privkey = process_ascii_key(
            key_data, self._gpgbinary, secret=True)
        pub_info, pubkey = process_ascii_key(
            key_data, self._gpgbinary, secret=False)

        if not pubkey:
            return (None, None)

        openpgp_privkey = None
        if privkey:
            # build private key
            openpgp_privkey = self._build_key_from_gpg(priv_info, privkey)
            leap_check(pub_info['fingerprint'] == priv_info['fingerprint'],
                       'Fingerprints for public and private key differ.',
                       errors.KeyFingerprintMismatch)
        # build public key
        openpgp_pubkey = self._build_key_from_gpg(pub_info, pubkey)

        return (openpgp_pubkey, openpgp_privkey)

    def put_ascii_key(self, key_data, address):
        """
        Put key contained in ascii-armored C{key_data} in local storage.

        :param key_data: The key data to be stored.
        :type key_data: str or unicode
        :param address: address for which this key will be active
        :type address: str

        :return: A Deferred which fires when the OpenPGPKey is in the storage.
        :rtype: Deferred
        """
        leap_assert_type(key_data, (str, unicode))

        openpgp_privkey = None
        try:
            openpgp_pubkey, openpgp_privkey = self.parse_ascii_key(key_data)
        except (errors.KeyAddressMismatch, errors.KeyFingerprintMismatch) as e:
            return defer.fail(e)

        def put_key(_, key):
            return self.put_key(key, address)

        d = defer.succeed(None)
        if openpgp_pubkey is not None:
            d.addCallback(put_key, openpgp_pubkey)
        if openpgp_privkey is not None:
            d.addCallback(put_key, openpgp_privkey)
        return d

    def put_key(self, key, address):
        """
        Put C{key} in local storage.

        :param key: The key to be stored.
        :type key: OpenPGPKey
        :param address: address for which this key will be active.
        :type address: str

        :return: A Deferred which fires when the key is in the storage.
        :rtype: Deferred
        """
        d = self._put_key_doc(key)
        d.addCallback(lambda _: self._put_active_doc(key, address))
        return d

    def _put_key_doc(self, key):
        """
        Put key document in soledad

        :type key: OpenPGPKey
        :rtype: Deferred
        """
        def check_and_put(docs, key):
            deferred_repair = defer.succeed(None)
            if len(docs) == 0:
                return self._soledad.create_doc_from_json(key.get_json())
            elif len(docs) > 1:
                deferred_repair = self._repair_key_docs(docs, key.key_id)

            doc = docs[0]
            oldkey = build_key_from_dict(OpenPGPKey, doc.content)
            if key.fingerprint != oldkey.fingerprint:
                logger.critical(
                    "Can't put a key whith the same key_id and different "
                    "fingerprint: %s, %s"
                    % (key.fingerprint, oldkey.fingerprint))
                return defer.fail(
                    errors.KeyFingerprintMismatch(key.fingerprint))

            # in case of an update of the key merge them with gnupg
            with TempGPGWrapper(gpgbinary=self._gpgbinary) as gpg:
                gpg.import_keys(oldkey.key_data)
                gpg.import_keys(key.key_data)
                gpgkey = gpg.list_keys(secret=key.private).pop()
                mergedkey = self._build_key_from_gpg(
                    gpgkey,
                    gpg.export_keys(gpgkey['fingerprint'],
                                    secret=key.private))
            mergedkey.validation = max(
                [key.validation, oldkey.validation])
            mergedkey.last_audited_at = oldkey.last_audited_at
            mergedkey.refreshed_at = key.refreshed_at
            mergedkey.encr_used = key.encr_used or oldkey.encr_used
            mergedkey.sign_used = key.sign_used or oldkey.sign_used
            doc.set_json(mergedkey.get_json())
            deferred_put = self._soledad.put_doc(doc)

            d = defer.gatherResults([deferred_put, deferred_repair])
            d.addCallback(lambda res: res[0])
            return d

        d = self._soledad.get_from_index(
            TYPE_ID_PRIVATE_INDEX,
            self.KEY_TYPE,
            key.key_id,
            '1' if key.private else '0')
        d.addCallback(check_and_put, key)
        return d

    def _put_active_doc(self, key, address):
        """
        Put active key document in soledad

        :type key: OpenPGPKey
        :type addresses: str
        :rtype: Deferred
        """
        def check_and_put(docs):
            if len(docs) == 1:
                doc = docs.pop()
                doc.set_json(key.get_active_json(address))
                d = self._soledad.put_doc(doc)
            else:
                if len(docs) > 1:
                    logger.error("There is more than one active key document "
                                 "for the address %s" % (address,))
                    deferreds = []
                    for doc in docs:
                        delete = self._soledad.delete_doc(doc)
                        deferreds.append(delete)
                    d = defer.gatherResults(deferreds, consumeErrors=True)
                else:
                    d = defer.succeed(None)

                d.addCallback(
                    lambda _: self._soledad.create_doc_from_json(
                        key.get_active_json(address)))
            return d

        d = self._soledad.get_from_index(
            TYPE_ADDRESS_PRIVATE_INDEX,
            self.ACTIVE_TYPE,
            address,
            '1' if key.private else '0')
        d.addCallback(check_and_put)
        return d

    def _get_key_doc(self, address, private=False):
        """
        Get the document with a key (public, by default) bound to C{address}.

        If C{private} is True, looks for a private key instead of a public.

        :param address: The address bound to the key.
        :type address: str
        :param private: Whether to look for a private key.
        :type private: bool

        :return: A Deferred which fires with the SoledadDocument with the key
                 or None if it does not exist.
        :rtype: Deferred
        """
        def get_key_from_active_doc(activedoc):
            if len(activedoc) is 0:
                return None
            leap_assert(
                len(activedoc) is 1,
                'Found more than one key for address %s!' % (address,))

            key_id = activedoc[0].content[KEY_ID_KEY]
            d = self._soledad.get_from_index(
                TYPE_ID_PRIVATE_INDEX,
                self.KEY_TYPE,
                key_id,
                '1' if private else '0')
            d.addCallback(get_doc, key_id, activedoc)
            return d

        def get_doc(doclist, key_id, activedoc):
            if len(doclist) == 0:
                logger.warning('There is no key for id %s! Self-repairing it.'
                               % (key_id))
                d = self._soledad.delete_doc(activedoc)
                d.addCallback(lambda _: None)
                return d
            elif len(doclist) > 1:
                d = self._repair_key_docs(doclist, key_id)
                d.addCallback(lambda _: doclist[0])
                return d
            return doclist[0]

        d = self._soledad.get_from_index(
            TYPE_ADDRESS_PRIVATE_INDEX,
            self.ACTIVE_TYPE,
            address,
            '1' if private else '0')
        d.addCallback(get_key_from_active_doc)
        return d

    def _build_key_from_gpg(self, key, key_data):
        """
        Build an OpenPGPKey for C{address} based on C{key} from
        local gpg storage.

        ASCII armored GPG key data has to be queried independently in this
        wrapper, so we receive it in C{key_data}.

        :param key: Key obtained from GPG storage.
        :type key: dict
        :param key_data: Key data obtained from GPG storage.
        :type key_data: str
        :return: An instance of the key.
        :rtype: OpenPGPKey
        """
        return build_gpg_key(key, key_data, self._gpgbinary)

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
        leap_assert_type(key, OpenPGPKey)

        def delete_docs(activedocs):
            deferreds = []
            for doc in activedocs:
                d = self._soledad.delete_doc(doc)
                deferreds.append(d)
            return defer.gatherResults(deferreds)

        def get_key_docs(_):
            return self._soledad.get_from_index(
                TYPE_ID_PRIVATE_INDEX,
                self.KEY_TYPE,
                key.key_id,
                '1' if key.private else '0')

        def delete_key(docs):
            if len(docs) == 0:
                raise errors.KeyNotFound(key)
            elif len(docs) > 1:
                logger.warning("There is more than one key for key_id %s"
                               % key.key_id)

            has_deleted = False
            deferreds = []
            for doc in docs:
                if doc.content['fingerprint'] == key.fingerprint:
                    d = self._soledad.delete_doc(doc)
                    deferreds.append(d)
                    has_deleted = True
            if not has_deleted:
                raise errors.KeyNotFound(key)
            return defer.gatherResults(deferreds)

        d = self._soledad.get_from_index(
            TYPE_ID_PRIVATE_INDEX,
            self.ACTIVE_TYPE,
            key.key_id,
            '1' if key.private else '0')
        d.addCallback(delete_docs)
        d.addCallback(get_key_docs)
        d.addCallback(delete_key)
        return d

    def _repair_key_docs(self, doclist, key_id):
        """
        If there is more than one key for a key id try to self-repair it

        :return: a Deferred that will be fired once all the deletions are
                 completed
        :rtype: Deferred
        """
        logger.error("BUG ---------------------------------------------------")
        logger.error("There is more than one key with the same key_id %s:"
                     % (key_id,))

        def log_key_doc(doc):
            logger.error("\t%s: %s" % (doc.content[KEY_ADDRESS_KEY],
                                       doc.content[KEY_FINGERPRINT_KEY]))

        doclist.sort(key=lambda doc: doc.content[KEY_REFRESHED_AT_KEY],
                     reverse=True)
        log_key_doc(doclist[0])
        deferreds = []
        for doc in doclist[1:]:
            log_key_doc(doc)
            d = self._soledad.delete_doc(doc)
            deferreds.append(d)

        logger.error("")
        logger.error(traceback.extract_stack())
        logger.error("BUG (please report above info) ------------------------")
        return defer.gatherResults(deferreds, consumeErrors=True)

    #
    # Data encryption, decryption, signing and verifying
    #

    @staticmethod
    def _assert_gpg_result_ok(result):
        """
        Check if GPG result is 'ok' and log stderr outputs.

        :param result: GPG results, which have a field calld 'ok' that states
                       whether the gpg operation was successful or not.
        :type result: object

        :raise GPGError: Raised when the gpg operation was not successful.
        """
        stderr = getattr(result, 'stderr', None)
        if stderr:
            logger.debug("%s" % (stderr,))
        if getattr(result, 'ok', None) is not True:
            raise errors.GPGError(
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

        :raise EncryptError: Raised if failed encrypting for some reason.
        """
        leap_assert_type(pubkey, OpenPGPKey)
        leap_assert(pubkey.private is False, 'Key is not public.')
        keys = [pubkey]
        if sign is not None:
            leap_assert_type(sign, OpenPGPKey)
            leap_assert(sign.private is True)
            keys.append(sign)
        with TempGPGWrapper(keys, self._gpgbinary) as gpg:
            result = gpg.encrypt(
                data, pubkey.fingerprint,
                default_key=sign.key_id if sign else None,
                passphrase=passphrase, symmetric=False,
                cipher_algo=cipher_algo)
            # Here we cannot assert for correctness of sig because the sig is
            # in the ciphertext.
            # result.ok    - (bool) indicates if the operation succeeded
            # result.data  - (bool) contains the result of the operation
            try:
                self._assert_gpg_result_ok(result)
                return result.data
            except errors.GPGError as e:
                logger.error('Failed to decrypt: %s.' % str(e))
                raise errors.EncryptError()

    def decrypt(self, data, privkey, passphrase=None, verify=None):
        """
        Decrypt C{data} using private @{privkey} and verify with C{verify} key.

        :param data: The data to be decrypted.
        :type data: str
        :param privkey: The key used to decrypt.
        :type privkey: OpenPGPKey
        :param passphrase: The passphrase for the secret key used for
                           decryption.
        :type passphrase: str
        :param verify: The key used to verify a signature.
        :type verify: OpenPGPKey

        :return: The decrypted data and if signature verifies
        :rtype: (unicode, bool)

        :raise DecryptError: Raised if failed decrypting for some reason.
        """
        leap_assert(privkey.private is True, 'Key is not private.')
        keys = [privkey]
        if verify is not None:
            leap_assert_type(verify, OpenPGPKey)
            leap_assert(verify.private is False)
            keys.append(verify)
        with TempGPGWrapper(keys, self._gpgbinary) as gpg:
            try:
                result = gpg.decrypt(
                    data, passphrase=passphrase, always_trust=True)
                self._assert_gpg_result_ok(result)

                # verify signature
                sign_valid = False
                if (verify is not None and
                        result.valid is True and
                        verify.fingerprint == result.pubkey_fingerprint):
                    sign_valid = True

                return (result.data, sign_valid)
            except errors.GPGError as e:
                logger.error('Failed to decrypt: %s.' % str(e))
                raise errors.DecryptError(str(e))

    def is_encrypted(self, data):
        """
        Return whether C{data} was asymmetrically encrypted using OpenPGP.

        :param data: The data we want to know about.
        :type data: str

        :return: Whether C{data} was encrypted using this wrapper.
        :rtype: bool
        """
        with TempGPGWrapper(gpgbinary=self._gpgbinary) as gpg:
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
        with TempGPGWrapper(privkey, self._gpgbinary) as gpg:
            result = gpg.sign(data, default_key=privkey.key_id,
                              digest_algo=digest_algo, clearsign=clearsign,
                              detach=detach, binary=binary)
            rfprint = privkey.fingerprint
            privkey = gpg.list_keys(secret=True).pop()
            kfprint = privkey['fingerprint']
            if result.fingerprint is None:
                raise errors.SignFailed(
                    'Failed to sign with key %s: %s' %
                    (privkey['keyid'], result.stderr))
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

        :return: signature matches
        :rtype: bool
        """
        leap_assert_type(pubkey, OpenPGPKey)
        leap_assert(pubkey.private is False)
        with TempGPGWrapper(pubkey, self._gpgbinary) as gpg:
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
                result = gpg.verify_file(io.BytesIO(data), sig_file=sfname)
                os.unlink(sfname)
            gpgpubkey = gpg.list_keys().pop()
            valid = result.valid
            rfprint = result.fingerprint
            kfprint = gpgpubkey['fingerprint']
            return valid and rfprint == kfprint


def process_ascii_key(key_data, gpgbinary, secret=False):
    with TempGPGWrapper(gpgbinary=gpgbinary) as gpg:
        try:
            gpg.import_keys(key_data)
            info = gpg.list_keys(secret=secret).pop()
            key = gpg.export_keys(info['fingerprint'], secret=secret)
        except IndexError:
            info = {}
            key = None
    return info, key


def build_gpg_key(key_info, key_data, gpgbinary=None):
    expiry_date = None
    if key_info['expires']:
        expiry_date = datetime.fromtimestamp(int(key_info['expires']))
    address = []
    for uid in key_info['uids']:
        address.append(_parse_address(uid))

    return OpenPGPKey(
        address,
        gpgbinary=gpgbinary,
        key_id=key_info['keyid'],
        fingerprint=key_info['fingerprint'],
        key_data=key_data,
        private=True if key_info['type'] == 'sec' else False,
        length=int(key_info['length']),
        expiry_date=expiry_date,
        refreshed_at=datetime.now())
