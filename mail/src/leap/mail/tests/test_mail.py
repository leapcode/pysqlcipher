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
from functools import partial

from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.mail import MessageCollection
from leap.mail.mailbox_indexer import MailboxIndexer
from leap.mail.tests.common import SoledadTestMixin

from twisted.internet import defer
from twisted.trial import unittest

HERE = os.path.split(os.path.abspath(__file__))[0]


class MessageCollectionTestCase(unittest.TestCase, SoledadTestMixin):
    """
    Tests for the SoledadDocumentWrapper.
    """

    def get_collection(self, mbox_collection=True):
        """
        Get a collection for tests.
        """
        adaptor = SoledadMailAdaptor()
        store = self._soledad
        adaptor.store = store
        if mbox_collection:
            mbox_indexer = MailboxIndexer(store)
            mbox_name = "TestMbox"
        else:
            mbox_indexer = mbox_name = None

        def get_collection_from_mbox_wrapper(wrapper):
            return MessageCollection(
                adaptor, store,
                mbox_indexer=mbox_indexer, mbox_wrapper=wrapper)

        d = adaptor.initialize_store(store)
        if mbox_collection:
            d.addCallback(lambda _: mbox_indexer.create_table(mbox_name))
        d.addCallback(lambda _: adaptor.get_or_create_mbox(store, mbox_name))
        d.addCallback(get_collection_from_mbox_wrapper)
        return d

    def test_is_mailbox_collection(self):

        def assert_is_mbox_collection(collection):
            self.assertTrue(collection.is_mailbox_collection())

        d = self.get_collection()
        d.addCallback(assert_is_mbox_collection)
        return d

    def assert_collection_count(self, _, expected, collection):

        def _assert_count(count):
            self.assertEqual(count, expected)
        d = collection.count()
        d.addCallback(_assert_count)
        return d

    def test_add_msg(self):

        with open(os.path.join(HERE, "rfc822.message")) as f:
            raw = f.read()

        def add_msg_to_collection_and_assert_count(collection):
            d = collection.add_msg(raw)
            d.addCallback(partial(
                self.assert_collection_count,
                expected=1, collection=collection))
            return d

        d = self.get_collection()
        d.addCallback(add_msg_to_collection_and_assert_count)
        return d
