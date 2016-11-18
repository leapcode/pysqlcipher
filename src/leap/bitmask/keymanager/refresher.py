# -*- coding: utf-8 -*-
# refresher.py
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
A service which continuous refreshes the (public) key directories randomly in a
random time interval.
"""

from twisted.internet.task import LoopingCall
from twisted.logger import Logger
from twisted.internet import defer
from random import choice, randrange

DEBUG_STOP_REFRESH = "Stop to refresh the key directory ..."
DEBUG_START_REFRESH = "Start to refresh the key directory ..."
ERROR_UNEQUAL_FINGERPRINTS = "[WARNING] Your provider might be cheat " \
                             "on you, and gave a wrong key back. " \
                             "Fingerprints are unequal, old %s new %s "

MIN_RANDOM_INTERVAL_RANGE = 4 * 60  # four minutes
MAX_RANDOM_INTERVAL_RANGE = 6 * 60  # six minutes

logger = Logger()


class RandomRefreshPublicKey(object):

    def __init__(self, openpgp, keymanager):
        """
        Initialize the RandomRefreshPublicKey.
        :param openpgp: Openpgp object.
        :param keymanager: The key manager.
        """
        self._openpgp = openpgp
        self._keymanger = keymanager
        self._loop = LoopingCall(self._refresh_continuous)
        self._loop.interval = self._get_random_interval_to_refresh()

    def start(self):
        """
        Start the looping call with random interval
        [MIN_RANDOM_INTERVAL_RANGE, MAX_RANDOM_INTERVAL_RANGE]
        :return: LoopingCall to start the service.
        :rtype: A deferred.
        """
        self._loop.start(self._get_random_interval_to_refresh(), False)
        logger.debug(DEBUG_START_REFRESH)

    def stop(self):
        """
        Stop the looping call with random interval.
        """
        self._loop.stop()
        logger.debug(DEBUG_STOP_REFRESH)

    @defer.inlineCallbacks
    def _get_random_key(self):
        """
        Get a random key of all the keys in a users key doc.
        :return: A random key.
        :rtype: A deferred.
        """
        keys = yield self._openpgp.get_all_keys()
        defer.returnValue(None if keys is None or keys == [] else choice(keys))

    @defer.inlineCallbacks
    def _refresh_continuous(self):
        """
        The LoopingCall to refresh the key doc continuously.
        """
        self._loop.interval = self._get_random_interval_to_refresh()
        yield self.maybe_refresh_key()

    @defer.inlineCallbacks
    def _maybe_unactivate_key(self, key):
        """
        Unactivate a given key.
        :param key: The key to be unactivated.
        """
        if key.is_expired() and key.is_active():  # TODO or is_revoked
            yield self._openpgp.unactivate_key(key.address)
            key.set_unactive()

    @defer.inlineCallbacks
    def maybe_refresh_key(self):
        """
        Get key from nicknym and try to refresh.
        """
        old_key = yield self._get_random_key()

        if old_key is None:
            defer.returnValue(None)

        old_updated_key = yield self._keymanger._nicknym.\
            fetch_key_with_fingerprint(old_key.fingerprint)

        if old_updated_key.fingerprint != old_key.fingerprint:
            logger.error(ERROR_UNEQUAL_FINGERPRINTS %
                         (old_key.fingerprint, old_updated_key.fingerprint))
            defer.returnValue(None)

        yield self._maybe_unactivate_key(old_updated_key)
        yield self._openpgp.put_key(old_updated_key)

        # No new fetch by address needed, bc that will happen before sending an
        # email could be discussed since fetching before sending an email
        # leaks information.

    def _get_random_interval_to_refresh(self):
        """
        Return a random quantity, in minutes, to be used as the refresh
        interval.

        :return: A random integer, in the interval defined by the constants
        (MIN_RANDOM_INTERVAL_RANGE, MAX_RANDOM_INTERVAL_RANGE).
        """
        return randrange(MIN_RANDOM_INTERVAL_RANGE, MAX_RANDOM_INTERVAL_RANGE)
