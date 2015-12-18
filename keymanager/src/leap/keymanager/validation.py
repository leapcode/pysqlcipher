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
    https://leap.se/en/docs/design/transitional-key-validation
"""


from datetime import datetime


class ValidationLevel(object):
    """
    A validation level

    Meant to be used to compare levels or get its string representation.
    """
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __cmp__(self, other):
        return cmp(self.value, other.value)

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<ValidationLevel: %s (%d)>" % (self.name, self.value)


class _ValidationLevels(object):
    """
    Handler class to manage validation levels. It should have only one global
    instance 'ValidationLevels'.

    The levels are attributes of the instance and can be used like:
       ValidationLevels.Weak_Chain
       ValidationLevels.get("Weak_Chain")
    """
    _level_names = ("Weak_Chain",
                    "Provider_Trust",
                    "Provider_Endorsement",
                    "Third_Party_Endorsement",
                    "Third_Party_Consensus",
                    "Historically_Auditing",
                    "Known_Key",
                    "Fingerprint")

    def __init__(self):
        for name in self._level_names:
            setattr(self, name,
                    ValidationLevel(name, self._level_names.index(name)))

    def get(self, name):
        """
        Get the ValidationLevel of a name

        :param name: name of the level
        :type name: str
        :rtype: ValidationLevel
        """
        return getattr(self, name)


ValidationLevels = _ValidationLevels()


def can_upgrade(new_key, old_key):
    """
    :type new_key: EncryptionKey
    :type old_key: EncryptionKey
    :rtype: bool
    """
    # First contact
    if old_key is None:
        return True

    # An update of the same key
    if new_key.fingerprint == old_key.fingerprint:
        return True

    # Manually verified fingerprint
    if new_key.validation == ValidationLevels.Fingerprint:
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

    # New key signed by the old key
    # XXX: signatures are using key-ids instead of fingerprints
    key_id = old_key.fingerprint[-16:]
    if key_id in new_key.signatures:
        return True

    return False
