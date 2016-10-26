# -*- coding: utf-8 -*-
# wrapper.py
# Copyright (C) 2016 LEAP
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
GPG wrapper for temporary keyrings
"""
import os
import platform
import shutil
import tempfile

from gnupg import GPG

from twisted.logger import Logger

from leap.common.check import leap_assert

try:
    from gnupg.gnupg import GPGUtilities
    GNUPG_NG = True
except ImportError:
    GNUPG_NG = False


logger = Logger()


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

        privfps = map(lambda privkey: privkey.fingerprint, privkeys)
        publkeys = filter(
            lambda pubkey: pubkey.fingerprint not in privfps, publkeys)

        listkeys = lambda: self._gpg.list_keys()
        listsecretkeys = lambda: self._gpg.list_keys(secret=True)

        try:
            self._gpg = GPG(binary=self._gpgbinary,
                            homedir=tempfile.mkdtemp())
        except TypeError:
            # compat-mode with python-gnupg until windows
            # support is fixed in gnupg-ng
            self._gpg = GPG(gpgbinary=self._gpgbinary,
                            gnupghome=tempfile.mkdtemp(),
                            options=[])

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
            try:
                homedir = self._gpg.homedir
            except AttributeError:
                homedir = self._gpg.gnupghome
            leap_assert(homedir != os.path.expanduser('~/.gnupg'),
                        "watch out! Tried to remove default gnupg home!")
            # TODO some windows debug ....
            homedir = os.path.normpath(homedir).replace("\\", "/")
            homedir = str(homedir.replace("c:/", "c://"))
            if platform.system() == "Windows":
                logger.error("BUG! Not erasing folder in Windows")
                return
            shutil.rmtree(homedir)
