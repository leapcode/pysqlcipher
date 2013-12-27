# -*- coding: utf-8 -*-
# index.py
# Copyright (C) 2013 LEAP
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
Index for SoledadBackedAccount, Mailbox and Messages.
"""
import logging

from leap.common.check import leap_assert, leap_assert_type

from leap.mail.imap.fields import fields


logger = logging.getLogger(__name__)


class IndexedDB(object):
    """
    Methods dealing with the index.

    This is a MixIn that needs access to the soledad instance,
    and also assumes that a INDEXES attribute is accessible to the instance.

    INDEXES must be a dictionary of type:
    {'index-name': ['field1', 'field2']}
    """
    # TODO we might want to move this to soledad itself, check

    def initialize_db(self):
        """
        Initialize the database.
        """
        leap_assert(self._soledad,
                    "Need a soledad attribute accesible in the instance")
        leap_assert_type(self.INDEXES, dict)

        # Ask the database for currently existing indexes.
        if not self._soledad:
            logger.debug("NO SOLEDAD ON IMAP INITIALIZATION")
            return
        db_indexes = dict()
        if self._soledad is not None:
            db_indexes = dict(self._soledad.list_indexes())
        for name, expression in fields.INDEXES.items():
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
