# -*- coding: utf-8 -*-
# test_mailbox_indexer.py
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
Tests for the mailbox_indexer module.
"""
import uuid
from functools import partial

from leap.mail import mailbox_indexer as mi
from leap.mail.tests.common import SoledadTestMixin

hash_test0 = '590c9f8430c7435807df8ba9a476e3f1295d46ef210f6efae2043a4c085a569e'
hash_test1 = '1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014'
hash_test2 = '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752'
hash_test3 = 'fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13'
hash_test4 = 'a4e624d686e03ed2767c0abd85c14426b0b1157d2ce81d27bb4fe4f6f01d688a'


def fmt_hash(mailbox_uuid, hash):
    return "M-" + mailbox_uuid.replace('-', '_') + "-" + hash

mbox_id = str(uuid.uuid4())


class MailboxIndexerTestCase(SoledadTestMixin):
    """
    Tests for the MailboxUID class.
    """
    def get_mbox_uid(self):
        m_uid = mi.MailboxIndexer(self._soledad)
        return m_uid

    def list_mail_tables_cb(self, ignored):
        def filter_mailuid_tables(tables):
            filtered = [
                table[0] for table in tables if
                table[0].startswith(mi.MailboxIndexer.table_preffix)]
            return filtered

        sql = "SELECT name FROM sqlite_master WHERE type='table';"
        d = self._soledad.raw_sqlcipher_query(sql)
        d.addCallback(filter_mailuid_tables)
        return d

    def select_uid_rows(self, mailbox):
        sql = "SELECT * FROM %s%s;" % (
            mi.MailboxIndexer.table_preffix, mailbox.replace('-', '_'))
        d = self._soledad.raw_sqlcipher_query(sql)
        return d

    def test_create_table(self):
        def assert_table_created(tables):
            self.assertEqual(
                tables, ["leapmail_uid_" + mbox_id.replace('-', '_')])

        m_uid = self.get_mbox_uid()
        d = m_uid.create_table(mbox_id)
        d.addCallback(self.list_mail_tables_cb)
        d.addCallback(assert_table_created)
        return d

    def test_create_and_delete_table(self):
        def assert_table_deleted(tables):
            self.assertEqual(tables, [])

        m_uid = self.get_mbox_uid()
        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.delete_table(mbox_id))
        d.addCallback(self.list_mail_tables_cb)
        d.addCallback(assert_table_deleted)
        return d

    def test_insert_doc(self):
        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)
        h4 = fmt_hash(mbox_id, hash_test3)
        h5 = fmt_hash(mbox_id, hash_test4)

        def assert_uid_rows(rows):
            expected = [(1, h1), (2, h2), (3, h3), (4, h4), (5, h5)]
            self.assertEquals(rows, expected)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h4))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h5))
        d.addCallback(lambda _: self.select_uid_rows(mbox_id))
        d.addCallback(assert_uid_rows)
        return d

    def test_insert_doc_return(self):
        m_uid = self.get_mbox_uid()

        def assert_rowid(rowid, expected=None):
            self.assertEqual(rowid, expected)

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(partial(assert_rowid, expected=1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(partial(assert_rowid, expected=2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(partial(assert_rowid, expected=3))
        return d

    def test_delete_doc(self):
        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)
        h4 = fmt_hash(mbox_id, hash_test3)
        h5 = fmt_hash(mbox_id, hash_test4)

        def assert_uid_rows(rows):
            expected = [(4, h4), (5, h5)]
            self.assertEquals(rows, expected)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h4))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h5))

        d.addCallbacks(lambda _: m_uid.delete_doc_by_uid(mbox_id, 1))
        d.addCallbacks(lambda _: m_uid.delete_doc_by_uid(mbox_id, 2))
        d.addCallbacks(lambda _: m_uid.delete_doc_by_hash(mbox_id, h3))

        d.addCallback(lambda _: self.select_uid_rows(mbox_id))
        d.addCallback(assert_uid_rows)
        return d

    def test_get_doc_id_from_uid(self):
        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)

        def assert_doc_hash(res):
            self.assertEqual(res, h1)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.get_doc_id_from_uid(mbox_id, 1))
        d.addCallback(assert_doc_hash)
        return d

    def test_count(self):
        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)
        h4 = fmt_hash(mbox_id, hash_test3)
        h5 = fmt_hash(mbox_id, hash_test4)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h4))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h5))

        def assert_count_after_inserts(count):
            self.assertEquals(count, 5)

        d.addCallback(lambda _: m_uid.count(mbox_id))
        d.addCallback(assert_count_after_inserts)

        d.addCallbacks(lambda _: m_uid.delete_doc_by_uid(mbox_id, 1))
        d.addCallbacks(lambda _: m_uid.delete_doc_by_uid(mbox_id, 2))

        def assert_count_after_deletions(count):
            self.assertEquals(count, 3)

        d.addCallback(lambda _: m_uid.count(mbox_id))
        d.addCallback(assert_count_after_deletions)
        return d

    def test_get_next_uid(self):
        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)
        h4 = fmt_hash(mbox_id, hash_test3)
        h5 = fmt_hash(mbox_id, hash_test4)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h4))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h5))

        def assert_next_uid(result, expected=1):
            self.assertEquals(result, expected)

        d.addCallback(lambda _: m_uid.get_next_uid(mbox_id))
        d.addCallback(partial(assert_next_uid, expected=6))
        return d

    def test_all_uid_iter(self):

        m_uid = self.get_mbox_uid()

        h1 = fmt_hash(mbox_id, hash_test0)
        h2 = fmt_hash(mbox_id, hash_test1)
        h3 = fmt_hash(mbox_id, hash_test2)
        h4 = fmt_hash(mbox_id, hash_test3)
        h5 = fmt_hash(mbox_id, hash_test4)

        d = m_uid.create_table(mbox_id)
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h1))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h2))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h3))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h4))
        d.addCallback(lambda _: m_uid.insert_doc(mbox_id, h5))
        d.addCallback(lambda _: m_uid.delete_doc_by_uid(mbox_id, 1))
        d.addCallback(lambda _: m_uid.delete_doc_by_uid(mbox_id, 4))

        def assert_all_uid(result, expected=[2, 3, 5]):
            self.assertEquals(result, expected)

        d.addCallback(lambda _: m_uid.all_uid_iter(mbox_id))
        d.addCallback(partial(assert_all_uid))
        return d
