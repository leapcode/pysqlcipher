# -*- coding: utf-8 -*-
# test_refresher.py
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
Tests for refreshing the key directory.
"""

import logging
from datetime import datetime

from mock import Mock, patch
from twisted.internet import defer

from common import KeyManagerWithSoledadTestCase, KEY_FINGERPRINT
from leap.keymanager import openpgp
from leap.keymanager.keys import OpenPGPKey
from leap.keymanager.refresher import RandomRefreshPublicKey, MIN_RANDOM_INTERVAL_RANGE, DEBUG_START_REFRESH, \
    DEBUG_STOP_REFRESH, ERROR_UNEQUAL_FINGERPRINTS

ANOTHER_FP = 'ANOTHERFINGERPRINT'

logger = logging.getLogger(__name__)


class RandomRefreshPublicKeyTestCase(KeyManagerWithSoledadTestCase):

    @defer.inlineCallbacks
    def test_get_random_address(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        rf = RandomRefreshPublicKey(pgp, self._key_manager())
        key = OpenPGPKey(address='user@leap.se')
        key_another = OpenPGPKey(address='zara@leap.se')

        pgp.get_all_keys = Mock(return_value=defer.succeed([key, key_another]))

        random_key = yield rf._get_random_key()
        self.assertTrue(random_key.address == key.address or random_key.address == key_another.address)

    @defer.inlineCallbacks
    def test_do_not_throw_error_for_empty_key_dict(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        rf = RandomRefreshPublicKey(pgp, self._key_manager())

        pgp.get_all_keys = Mock(return_value=defer.succeed([]))
        random_address = yield rf._get_random_key()
        self.assertTrue(random_address is None)

    @defer.inlineCallbacks
    def test_log_error_if_fetch_by_fingerprint_returns_wrong_key(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        km = self._key_manager()

        with patch.object(logging.Logger, 'error') as mock_logger_error:
            rf = RandomRefreshPublicKey(pgp, km)
            rf._get_random_key = \
                Mock(return_value=defer.succeed(OpenPGPKey(fingerprint=KEY_FINGERPRINT)))

            km._nicknym.fetch_key_with_fingerprint = \
                Mock(return_value=defer.succeed(OpenPGPKey(fingerprint=ANOTHER_FP)))

            yield rf.maybe_refresh_key()

            mock_logger_error.assert_called_with(ERROR_UNEQUAL_FINGERPRINTS %
                                                 (KEY_FINGERPRINT, ANOTHER_FP))

    @defer.inlineCallbacks
    def test_put_new_key_in_local_storage(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        km = self._key_manager()

        rf = RandomRefreshPublicKey(pgp, km)
        rf._get_random_key = Mock(return_value=defer.succeed(OpenPGPKey(fingerprint=KEY_FINGERPRINT)))

        km._nicknym.fetch_key_with_fingerprint = \
            Mock(return_value=defer.succeed(OpenPGPKey(fingerprint=ANOTHER_FP)))

        yield rf.maybe_refresh_key()

    @defer.inlineCallbacks
    def test_key_expired_will_be_deactivatet(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        km = self._key_manager()
        rf = RandomRefreshPublicKey(pgp, km)
        key = OpenPGPKey(address='zara@leap.se', expiry_date=datetime.now())

        self.assertTrue(key.address is 'zara@leap.se')

        km._openpgp.unactivate_key = Mock(return_value=defer.succeed(None))

        yield rf._maybe_unactivate_key(key)

        self.assertTrue(key.address is None)
        self.assertFalse(key.is_active())

    def test_start_refreshing(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)

        with patch.object(logging.Logger, 'debug') as mock_logger_start:
            rf = RandomRefreshPublicKey(pgp, self._key_manager())
            rf.start()
            mock_logger_start.assert_called_with(DEBUG_START_REFRESH)
            rf.stop()
            mock_logger_start.assert_called_with(DEBUG_STOP_REFRESH)

    def test_random_interval_is_set_properly(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        rf = RandomRefreshPublicKey(pgp, self._key_manager())
        self.assertTrue(rf._loop.interval >= MIN_RANDOM_INTERVAL_RANGE)

    def test_is_random_really_random(self):
        pgp = openpgp.OpenPGPScheme(
            self._soledad, gpgbinary=self.gpg_binary_path)
        rf = RandomRefreshPublicKey(pgp, self._key_manager())

        for x in range(0, 5):
            random_numbers = []

            for y in range(0, 5):
                random_numbers.append(rf._random_interval_to_refersh())

                # there are different numbers in the list
                if len(random_numbers) == len(set(random_numbers)) \
                        or len(random_numbers) == len(set(random_numbers)) + 1:
                    self.assertTrue(True)
                else:
                    self.assertTrue(False)


