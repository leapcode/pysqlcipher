# -*- coding: utf-8 -*-
# test_mail.py
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
Tests for the mail module.
"""
import os
import time
import uuid

from functools import partial
from email.parser import Parser
from email.Utils import formatdate

from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.mail import MessageCollection, Account, _unpack_headers
from leap.mail.mailbox_indexer import MailboxIndexer
from leap.mail.tests.common import SoledadTestMixin

HERE = os.path.split(os.path.abspath(__file__))[0]


def _get_raw_msg(multi=False):
    if multi:
        sample = "rfc822.multi.message"
    else:
        sample = "rfc822.message"
    with open(os.path.join(HERE, sample)) as f:
        raw = f.read()
    return raw


def _get_parsed_msg(multi=False):
    mail_parser = Parser()
    raw = _get_raw_msg(multi=multi)
    return mail_parser.parsestr(raw)


def _get_msg_time():
    timestamp = time.mktime((2010, 12, 12, 1, 1, 1, 1, 1, 1))
    return formatdate(timestamp)


class CollectionMixin(object):

    def get_collection(self, mbox_collection=True, mbox_name=None,
                       mbox_uuid=None):
        """
        Get a collection for tests.
        """
        adaptor = SoledadMailAdaptor()
        store = self._soledad
        adaptor.store = store

        if mbox_collection:
            mbox_indexer = MailboxIndexer(store)
            mbox_name = mbox_name or "TestMbox"
            mbox_uuid = mbox_uuid or str(uuid.uuid4())
        else:
            mbox_indexer = mbox_name = None

        def get_collection_from_mbox_wrapper(wrapper):
            wrapper.uuid = mbox_uuid
            return MessageCollection(
                adaptor, store,
                mbox_indexer=mbox_indexer, mbox_wrapper=wrapper)

        d = adaptor.initialize_store(store)
        if mbox_collection:
            d.addCallback(lambda _: mbox_indexer.create_table(mbox_uuid))
        d.addCallback(lambda _: adaptor.get_or_create_mbox(store, mbox_name))
        d.addCallback(get_collection_from_mbox_wrapper)
        return d


# TODO profile add_msg. Why are these tests so SLOW??!
class MessageTestCase(SoledadTestMixin, CollectionMixin):
    """
    Tests for the Message class.
    """
    msg_flags = ('\Recent', '\Unseen', '\TestFlag')
    msg_tags = ('important', 'todo', 'wonderful')
    internal_date = "19-Mar-2015 19:22:21 -0500"

    maxDiff = None

    def _do_insert_msg(self, multi=False):
        """
        Inserts and return a regular message, for tests.
        """
        def insert_message(collection):
            self._mbox_uuid = collection.mbox_uuid
            return collection.add_msg(
                raw, flags=self.msg_flags, tags=self.msg_tags,
                date=self.internal_date)

        raw = _get_raw_msg(multi=multi)

        d = self.get_collection()
        d.addCallback(insert_message)
        return d

    def get_inserted_msg(self, multi=False):
        d = self._do_insert_msg(multi=multi)
        d.addCallback(lambda _: self.get_collection(mbox_uuid=self._mbox_uuid))
        d.addCallback(lambda col: col.get_message_by_uid(1))
        return d

    def test_get_flags(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_get_flags_cb)
        return d

    def _test_get_flags_cb(self, msg):
        self.assertTrue(msg is not None)
        self.assertEquals(tuple(msg.get_flags()), self.msg_flags)

    def test_get_internal_date(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_get_internal_date_cb)

    def _test_get_internal_date_cb(self, msg):
        self.assertTrue(msg is not None)
        self.assertDictEqual(msg.get_internal_date(),
                             self.internal_date)

    def test_get_headers(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_get_headers_cb)
        return d

    def _test_get_headers_cb(self, msg):
        self.assertTrue(msg is not None)
        expected = [
            (str(key.lower()), str(value))
            for (key, value) in _get_parsed_msg().items()]
        self.assertItemsEqual(_unpack_headers(msg.get_headers()), expected)

    def test_get_body_file(self):
        d = self.get_inserted_msg(multi=True)
        d.addCallback(self._test_get_body_file_cb)
        return d

    def _test_get_body_file_cb(self, msg):
        self.assertTrue(msg is not None)
        orig = _get_parsed_msg(multi=True)
        expected = orig.get_payload()[0].get_payload()
        d = msg.get_body_file(self._soledad)

        def assert_body(fd):
            self.assertTrue(fd is not None)
            self.assertEqual(fd.read(), expected)
        d.addCallback(assert_body)
        return d

    def test_get_size(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_get_size_cb)
        return d

    def _test_get_size_cb(self, msg):
        self.assertTrue(msg is not None)
        expected = len(_get_parsed_msg().as_string())
        self.assertEqual(msg.get_size(), expected)

    def test_is_multipart_no(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_is_multipart_no_cb)
        return d

    def _test_is_multipart_no_cb(self, msg):
        self.assertTrue(msg is not None)
        expected = _get_parsed_msg().is_multipart()
        self.assertEqual(msg.is_multipart(), expected)

    def test_is_multipart_yes(self):
        d = self.get_inserted_msg(multi=True)
        d.addCallback(self._test_is_multipart_yes_cb)
        return d

    def _test_is_multipart_yes_cb(self, msg):
        self.assertTrue(msg is not None)
        expected = _get_parsed_msg(multi=True).is_multipart()
        self.assertEqual(msg.is_multipart(), expected)

    def test_get_subpart(self):
        d = self.get_inserted_msg(multi=True)
        d.addCallback(self._test_get_subpart_cb)
        return d

    def _test_get_subpart_cb(self, msg):
        self.assertTrue(msg is not None)

    def test_get_tags(self):
        d = self.get_inserted_msg()
        d.addCallback(self._test_get_tags_cb)
        return d

    def _test_get_tags_cb(self, msg):
        self.assertTrue(msg is not None)
        self.assertEquals(msg.get_tags(), self.msg_tags)


class MessageCollectionTestCase(SoledadTestMixin, CollectionMixin):
    """
    Tests for the MessageCollection class.
    """
    _mbox_uuid = None

    def assert_collection_count(self, _, expected):
        def _assert_count(count):
            self.assertEqual(count, expected)

        d = self.get_collection()
        d.addCallback(lambda col: col.count())
        d.addCallback(_assert_count)
        return d

    def add_msg_to_collection(self):
        raw = _get_raw_msg()

        def add_msg_to_collection(collection):
            # We keep the uuid in case we need to instantiate the same
            # collection afterwards.
            self._mbox_uuid = collection.mbox_uuid
            d = collection.add_msg(raw, date=_get_msg_time())
            return d

        d = self.get_collection()
        d.addCallback(add_msg_to_collection)
        return d

    def test_is_mailbox_collection(self):
        d = self.get_collection()
        d.addCallback(self._test_is_mailbox_collection_cb)
        return d

    def _test_is_mailbox_collection_cb(self, collection):
        self.assertTrue(collection.is_mailbox_collection())

    def test_get_uid_next(self):
        d = self.add_msg_to_collection()
        d.addCallback(lambda _: self.get_collection())
        d.addCallback(lambda col: col.get_uid_next())
        d.addCallback(self._test_get_uid_next_cb)

    def _test_get_uid_next_cb(self, next_uid):
        self.assertEqual(next_uid, 2)

    def test_add_and_count_msg(self):
        d = self.add_msg_to_collection()
        d.addCallback(self._test_add_and_count_msg_cb)
        return d

    def _test_add_and_count_msg_cb(self, _):
        return partial(self.assert_collection_count, expected=1)

    def test_copy_msg(self):
        # TODO ---- update when implementing messagecopier
        # interface
        pass
    test_copy_msg.skip = "Not yet implemented"

    def test_delete_msg(self):
        d = self.add_msg_to_collection()

        def del_msg(collection):
            def _delete_it(msg):
                self.assertTrue(msg is not None)
                return collection.delete_msg(msg)

            d = collection.get_message_by_uid(1)
            d.addCallback(_delete_it)
            return d

        # We need to instantiate an mbox collection with the same uuid that
        # the one in which we inserted the doc.
        d.addCallback(lambda _: self.get_collection(mbox_uuid=self._mbox_uuid))
        d.addCallback(del_msg)
        d.addCallback(self._test_delete_msg_cb)
        return d

    def _test_delete_msg_cb(self, _):
        return partial(self.assert_collection_count, expected=0)

    def test_update_flags(self):
        d = self.add_msg_to_collection()
        d.addCallback(self._test_update_flags_cb)
        return d

    def _test_update_flags_cb(self, msg):
        pass

    def test_update_tags(self):
        d = self.add_msg_to_collection()
        d.addCallback(self._test_update_tags_cb)
        return d

    def _test_update_tags_cb(self, msg):
        pass


class AccountTestCase(SoledadTestMixin):
    """
    Tests for the Account class.
    """
    def get_account(self, user_id):
        store = self._soledad
        return Account(store, user_id)

    def test_add_mailbox(self):
        acc = self.get_account('some_user_id')
        d = acc.callWhenReady(lambda _: acc.add_mailbox("TestMailbox"))
        d.addCallback(lambda _: acc.list_all_mailbox_names())
        d.addCallback(self._test_add_mailbox_cb)
        return d

    def _test_add_mailbox_cb(self, mboxes):
        expected = ['INBOX', 'TestMailbox']
        self.assertItemsEqual(mboxes, expected)

    def test_delete_mailbox(self):
        acc = self.get_account('some_user_id')
        d = acc.callWhenReady(lambda _: acc.delete_mailbox("Inbox"))
        d.addCallback(lambda _: acc.list_all_mailbox_names())
        d.addCallback(self._test_delete_mailbox_cb)
        return d

    def _test_delete_mailbox_cb(self, mboxes):
        expected = []
        self.assertItemsEqual(mboxes, expected)

    def test_rename_mailbox(self):
        acc = self.get_account('some_user_id')
        d = acc.callWhenReady(lambda _: acc.add_mailbox("OriginalMailbox"))
        d.addCallback(lambda _: acc.rename_mailbox(
            "OriginalMailbox", "RenamedMailbox"))
        d.addCallback(lambda _: acc.list_all_mailbox_names())
        d.addCallback(self._test_rename_mailbox_cb)
        return d

    def _test_rename_mailbox_cb(self, mboxes):
        expected = ['INBOX', 'RenamedMailbox']
        self.assertItemsEqual(mboxes, expected)

    def test_get_all_mailboxes(self):
        acc = self.get_account('some_user_id')
        d = acc.callWhenReady(lambda _: acc.add_mailbox("OneMailbox"))
        d.addCallback(lambda _: acc.add_mailbox("TwoMailbox"))
        d.addCallback(lambda _: acc.add_mailbox("ThreeMailbox"))
        d.addCallback(lambda _: acc.add_mailbox("anotherthing"))
        d.addCallback(lambda _: acc.add_mailbox("anotherthing2"))
        d.addCallback(lambda _: acc.get_all_mailboxes())
        d.addCallback(self._test_get_all_mailboxes_cb)
        return d

    def _test_get_all_mailboxes_cb(self, mailboxes):
        expected = ["INBOX", "OneMailbox", "TwoMailbox", "ThreeMailbox",
                    "anotherthing", "anotherthing2"]
        names = [m.mbox for m in mailboxes]
        self.assertItemsEqual(names, expected)

    def test_get_collection_by_mailbox(self):
        acc = self.get_account('some_user_id')
        d = acc.callWhenReady(lambda _: acc.get_collection_by_mailbox("INBOX"))
        d.addCallback(self._test_get_collection_by_mailbox_cb)
        return d

    def _test_get_collection_by_mailbox_cb(self, collection):
        self.assertTrue(collection.is_mailbox_collection())

        def assert_uid_next_empty_collection(uid):
            self.assertEqual(uid, 1)
        d = collection.get_uid_next()
        d.addCallback(assert_uid_next_empty_collection)
        return d

    def test_get_collection_by_docs(self):
        pass

    test_get_collection_by_docs.skip = "Not yet implemented"

    def test_get_collection_by_tag(self):
        pass

    test_get_collection_by_tag.skip = "Not yet implemented"
