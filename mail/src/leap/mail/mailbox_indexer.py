# -*- coding: utf-8 -*-
# mailbox_indexer.py
# Copyright (C) 2014 LEAP
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
Local tables to store the message Unique Identifiers for a given mailbox.
"""
import re

from leap.mail.constants import METAMSGID_RE


def _maybe_first_query_item(thing):
    """
    Return the first item the returned query result, or None
    if empty.
    """
    try:
        return thing[0][0]
    except IndexError:
        return None


class WrongMetaDocIDError(Exception):
    pass


class MailboxIndexer(object):
    """
    This class contains the commands needed to create, modify and alter the
    local-only UID tables for a given mailbox.

    Its purpouse is to keep a local-only index with the messages in each
    mailbox, mainly to satisfy the demands of the IMAP specification, but
    useful too for any effective listing of the messages in a mailbox.

    Since the incoming mail can be processed at any time in any replica, it's
    preferred not to attempt to maintain a global chronological global index.

    These indexes are Message Attributes needed for the IMAP specification (rfc
    3501), although they can be useful for other non-imap store
    implementations.
    """
    # The uids are expected to be 32-bits values, but the ROWIDs in sqlite
    # are 64-bit values. I *don't* think it really matters for any
    # practical use, but it's good to remmeber we've got that difference going
    # on.

    store = None
    table_preffix = "leapmail_uid_"

    def __init__(self, store):
        self.store = store

    def _query(self, *args, **kw):
        assert self.store is not None
        return self.store.raw_sqlcipher_query(*args, **kw)

    def create_table(self, mailbox):
        """
        Create the UID table for a given mailbox.
        :param mailbox: the mailbox name
        :type mailbox: str
        :rtype: Deferred
        """
        assert mailbox
        sql = ("CREATE TABLE if not exists {preffix}{name}( "
               "uid  INTEGER PRIMARY KEY AUTOINCREMENT, "
               "hash TEXT UNIQUE NOT NULL)".format(
                   preffix=self.table_preffix, name=mailbox))
        return self._query(sql)

    def delete_table(self, mailbox):
        """
        Delete the UID table for a given mailbox.
        :param mailbox: the mailbox name
        :type mailbox: str
        :rtype: Deferred
        """
        assert mailbox
        sql = ("DROP TABLE if exists {preffix}{name}".format(
            preffix=self.table_preffix, name=mailbox))
        return self._query(sql)

    def rename_table(self, oldmailbox, newmailbox):
        """
        Delete the UID table for a given mailbox.
        :param oldmailbox: the old mailbox name
        :type oldmailbox: str
        :param newmailbox: the new mailbox name
        :type newmailbox: str
        :rtype: Deferred
        """
        assert oldmailbox
        assert newmailbox
        assert oldmailbox != newmailbox
        sql = ("ALTER TABLE {preffix}{old} "
               "RENAME TO {preffix}{new}".format(
                   preffix=self.table_preffix,
                   old=oldmailbox, new=newmailbox))
        return self._query(sql)

    def insert_doc(self, mailbox, doc_id):
        """
        Insert the doc_id for a MetaMsg in the UID table for a given mailbox.

        The doc_id must be in the format:

            M+<mailbox>+<content-hash-of-the-message>

        :param mailbox: the mailbox name
        :type mailbox: str
        :param doc_id: the doc_id for the MetaMsg
        :type doc_id: str
        :return: a deferred that will fire with the uid of the newly inserted
                 document.
        :rtype: Deferred
        """
        assert mailbox
        assert doc_id

        if not re.findall(METAMSGID_RE.format(mbox=mailbox), doc_id):
            raise WrongMetaDocIDError("Wrong format for the MetaMsg doc_id")

        def get_rowid(result):
            return _maybe_first_query_item(result)

        sql = ("INSERT INTO {preffix}{name} VALUES ("
               "NULL, ?)".format(
                   preffix=self.table_preffix, name=mailbox))
        values = (doc_id,)

        sql_last = ("SELECT MAX(rowid) FROM {preffix}{name} "
                    "LIMIT 1;").format(
            preffix=self.table_preffix, name=mailbox)
        d = self._query(sql, values)
        d.addCallback(lambda _: self._query(sql_last))
        d.addCallback(get_rowid)
        return d

    def delete_doc_by_uid(self, mailbox, uid):
        """
        Delete the entry for a MetaMsg in the UID table for a given mailbox.

        :param mailbox: the mailbox name
        :type mailbox: str
        :param uid: the UID of the message.
        :type uid: int
        :rtype: Deferred
        """
        assert mailbox
        assert uid
        sql = ("DELETE FROM {preffix}{name} "
               "WHERE uid=?".format(
                   preffix=self.table_preffix, name=mailbox))
        values = (uid,)
        return self._query(sql, values)

    def delete_doc_by_hash(self, mailbox, doc_id):
        """
        Delete the entry for a MetaMsg in the UID table for a given mailbox.

        The doc_id must be in the format:

            M+<mailbox>+<content-hash-of-the-message>

        :param mailbox: the mailbox name
        :type mailbox: str
        :param doc_id: the doc_id for the MetaMsg
        :type doc_id: str
        :return: a deferred that will fire with the uid of the newly inserted
                 document.
        :rtype: Deferred
        """
        assert mailbox
        assert doc_id
        sql = ("DELETE FROM {preffix}{name} "
               "WHERE hash=?".format(
                   preffix=self.table_preffix, name=mailbox))
        values = (doc_id,)
        return self._query(sql, values)

    def get_doc_id_from_uid(self, mailbox, uid):
        """
        Get the doc_id for a MetaMsg in the UID table for a given mailbox.

        :param mailbox: the mailbox name
        :type mailbox: str
        :param uid: the uid for the MetaMsg for this mailbox
        :type uid: int
        :rtype: Deferred
        """
        def get_hash(result):
            return _maybe_first_query_item(result)

        sql = ("SELECT hash from {preffix}{name} "
               "WHERE uid=?".format(
                   preffix=self.table_preffix, name=mailbox))
        values = (uid,)
        d = self._query(sql, values)
        d.addCallback(get_hash)
        return d

    def get_doc_ids_from_uids(self, mailbox, uids):
        # For IMAP relative numbering /sequences.
        # XXX dereference the range (n,*)
        raise NotImplementedError()

    def count(self, mailbox):
        """
        Get the number of entries in the UID table for a given mailbox.

        :param mailbox: the mailbox name
        :type mailbox: str
        :return: a deferred that will fire with an integer returning the count.
        :rtype: Deferred
        """
        def get_count(result):
            return _maybe_first_query_item(result)

        sql = ("SELECT Count(*) FROM {preffix}{name};".format(
            preffix=self.table_preffix, name=mailbox))
        d = self._query(sql)
        d.addCallback(get_count)
        return d

    def get_next_uid(self, mailbox):
        """
        Get the next integer beyond the highest UID count for a given mailbox.

        This is expected by the IMAP implementation. There are no guarantees
        that a document to be inserted in the future gets the returned UID: the
        only thing that can be assured is that it will be equal or greater than
        the value returned.

        :param mailbox: the mailbox name
        :type mailbox: str
        :return: a deferred that will fire with an integer returning the next
                 uid.
        :rtype: Deferred
        """
        assert mailbox

        def increment(result):
            uid = _maybe_first_query_item(result)
            if uid is None:
                return None
            return uid + 1

        sql = ("SELECT MAX(rowid) FROM {preffix}{name} "
               "LIMIT 1;").format(
            preffix=self.table_preffix, name=mailbox)

        d = self._query(sql)
        d.addCallback(increment)
        return d
