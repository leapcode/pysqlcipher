# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2014 LEAP
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
Validation levels implementation for key managment.

See:
    https://lists.riseup.net/www/arc/leap-discuss/2014-09/msg00000.html
"""


from datetime import datetime
from enum import Enum


ValidationLevel = Enum(
    "Weak_Chain",
    "Provider_Trust",
    "Provider_Endorsement",
    "Third_Party_Endorsement",
    "Third_Party_Consensus",
    "Historically_Auditing",
    "Known_Key",
    "Fingerprint")


def toValidationLevel(value):
    """
    Convert a string representation of a validation level into
    C{ValidationLevel}

    :param value: validation level
    :type value: str
    :rtype: ValidationLevel
    :raises ValueError: if C{value} is not a validation level
    """
    for level in ValidationLevel:
        if value == str(level):
            return level
    raise ValueError("Not valid validation level: %s" % (value,))


def can_upgrade(new_key, old_key):
    """
    :type new_key: EncryptionKey
    :type old_key: EncryptionKey
    :rtype: bool
    """
    # XXX implement key signature checking (#6120)

    # First contact
    if old_key is None:
        return True

    # An update of the same key
    if new_key.fingerprint == old_key.fingerprint:
        return True

    # Manually verified fingerprint
    if new_key.validation == ValidationLevel.Fingerprint:
        return True

    # Expired key and higher validation level
    if (old_key.expiry_date is not None and
            old_key.expiry_date < datetime.now() and
            new_key.validation >= old_key.validation):
        return True

    # No expiration date and higher validation level
    if (old_key.expiry_date is None and
            new_key.validation > old_key.validation):
        return True

    # Not successfully used and strict high validation level
    if (not (old_key.sign_used and old_key.encr_used) and
            new_key.validation > old_key.validation):
        return True

    return False
