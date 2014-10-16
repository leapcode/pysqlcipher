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

from twisted.internet import defer

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

    _index_creation_deferreds = []
    index_ready = False

    def initialize_db(self):
        """
        Initialize the database.
        """
        leap_assert(self._soledad,
                    "Need a soledad attribute accesible in the instance")
        leap_assert_type(self.INDEXES, dict)
        self._index_creation_deferreds = []

        def _on_indexes_created(ignored):
            self.index_ready = True

        def _create_index(name, expression):
            d = self._soledad.create_index(name, *expression)
            self._index_creation_deferreds.append(d)

        def _create_indexes(db_indexes):
            db_indexes = dict(db_indexes)
            for name, expression in fields.INDEXES.items():
                if name not in db_indexes:
                    # The index does not yet exist.
                    _create_index(name, expression)
                    continue

                if expression == db_indexes[name]:
                    # The index exists and is up to date.
                    continue
                # The index exists but the definition is not what expected, so
                # we delete it and add the proper index expression.
                d1 = self._soledad.delete_index(name)
                d1.addCallback(lambda _: _create_index(name, expression))

            all_created = defer.gatherResults(self._index_creation_deferreds)
            all_created.addCallback(_on_indexes_created)
            return all_created

        # Ask the database for currently existing indexes.
        if not self._soledad:
            logger.debug("NO SOLEDAD ON IMAP INITIALIZATION")
            return
        if self._soledad is not None:
            d = self._soledad.list_indexes()
            d.addCallback(_create_indexes)
            return d
