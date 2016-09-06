# -*- coding: utf-8 -*-
# conftest.py
# Copyright (C) 2016 LEAP Encryption Acess Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Fixtures for the benchmarks for leap.bitmask.keymanager
"""

import pytest

from leap.bitmask.keymanager.keys import build_key_from_dict
from leap.bitmask.keymanager.wrapper import TempGPGWrapper

from common import ADDRESS
from common import KEY_FINGERPRINT
from common import PUBLIC_KEY
from common import PRIVATE_KEY
from common import ADDRESS_2
from common import KEY_FINGERPRINT_2
from common import PUBLIC_KEY_2
from common import PRIVATE_KEY_2


@pytest.fixture
def wrapper(keys=None):
    return TempGPGWrapper(keys=keys)


def _get_key(address, key_fingerprint, key_data, private):
    kdict = {
        'uids': [address],
        'fingerprint': key_fingerprint,
        'key_data': key_data,
        'private': private,
        'length': 4096,
        'expiry_date': 0,
        'refreshed_at': 1311239602,
    }
    key = build_key_from_dict(kdict)
    return key


@pytest.fixture
def public_key():
    return _get_key(ADDRESS, KEY_FINGERPRINT, PUBLIC_KEY, False)


@pytest.fixture
def public_key_2():
    return _get_key(ADDRESS_2, KEY_FINGERPRINT_2, PUBLIC_KEY_2, False)


@pytest.fixture
def openpgp_keys():
    return [
        _get_key(ADDRESS, KEY_FINGERPRINT, PUBLIC_KEY, False),
        _get_key(ADDRESS_2, KEY_FINGERPRINT_2, PUBLIC_KEY_2, False),
        _get_key(ADDRESS, KEY_FINGERPRINT, PRIVATE_KEY, True),
        _get_key(ADDRESS_2, KEY_FINGERPRINT_2, PRIVATE_KEY_2, True),
    ]
