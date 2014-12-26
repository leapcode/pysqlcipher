# -*- coding: utf-8 -*-
# test_soledad_adaptor.py
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
Tests for the Soledad Adaptor module - leap.mail.adaptors.soledad
"""
import os
from functools import partial

from twisted.internet import defer
from twisted.trial import unittest

from leap.mail.adaptors import models
from leap.mail.adaptors.soledad import SoledadDocumentWrapper
from leap.mail.adaptors.soledad import SoledadIndexMixin
from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.tests.common import SoledadTestMixin

# DEBUG
# import logging
# logging.basicConfig(level=logging.DEBUG)


class CounterWrapper(SoledadDocumentWrapper):
    class model(models.SerializableModel):
        counter = 0
        flag = None


class CharacterWrapper(SoledadDocumentWrapper):
    class model(models.SerializableModel):
        name = ""
        age = 20


class ActorWrapper(SoledadDocumentWrapper):
    class model(models.SerializableModel):
        type_ = "actor"
        name = None

        class __meta__(object):
            index = "name"
            list_index = ("by-type", "type_")


class TestAdaptor(SoledadIndexMixin):
    indexes = {'by-name': ['name'],
               'by-type-and-name': ['type', 'name'],
               'by-type': ['type']}


class SoledadDocWrapperTestCase(unittest.TestCase, SoledadTestMixin):
    """
    Tests for the SoledadDocumentWrapper.
    """
    def assert_num_docs(self, num, docs):
        self.assertEqual(len(docs[1]), num)

    def test_create_single(self):

        store = self._soledad
        wrapper = CounterWrapper()

        def assert_one_doc(docs):
            self.assertEqual(docs[0], 1)

        d = wrapper.create(store)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(assert_one_doc)
        return d

    def test_create_many(self):

        store = self._soledad
        w1 = CounterWrapper()
        w2 = CounterWrapper(counter=1)
        w3 = CounterWrapper(counter=2)
        w4 = CounterWrapper(counter=3)
        w5 = CounterWrapper(counter=4)

        d1 = [w1.create(store),
              w2.create(store),
              w3.create(store),
              w4.create(store),
              w5.create(store)]

        d = defer.gatherResults(d1)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 5))
        return d

    def test_multiple_updates(self):

        store = self._soledad
        wrapper = CounterWrapper(counter=1)
        MAX = 100

        def assert_doc_id(doc):
            self.assertTrue(wrapper._doc_id is not None)
            return doc

        def assert_counter_initial_ok(doc):
            self.assertEqual(wrapper.counter, 1)

        def increment_counter(ignored):
            d1 = []

            def record_revision(revision):
                rev = int(revision.split(':')[1])
                self.results.append(rev)

            for i in list(range(MAX)):
                wrapper.counter += 1
                wrapper.flag = i % 2 == 0
                d = wrapper.update(store)
                d.addCallback(record_revision)
                d1.append(d)

            return defer.gatherResults(d1)

        def assert_counter_final_ok(doc):
            self.assertEqual(doc.content['counter'], MAX + 1)
            self.assertEqual(doc.content['flag'], False)

        def assert_results_ordered_list(ignored):
            self.assertEqual(self.results, sorted(range(2, MAX + 2)))

        d = wrapper.create(store)
        d.addCallback(assert_doc_id)
        d.addCallback(assert_counter_initial_ok)
        d.addCallback(increment_counter)
        d.addCallback(lambda _: store.get_doc(wrapper._doc_id))
        d.addCallback(assert_counter_final_ok)
        d.addCallback(assert_results_ordered_list)
        return d

    def test_delete(self):
        adaptor = TestAdaptor()
        store = self._soledad

        wrapper_list = []

        def get_or_create_bob(ignored):
            def add_to_list(wrapper):
                wrapper_list.append(wrapper)
                return wrapper
            wrapper = CharacterWrapper.get_or_create(
                store, 'by-name', 'bob')
            wrapper.addCallback(add_to_list)
            return wrapper

        def delete_bob(ignored):
            wrapper = wrapper_list[0]
            return wrapper.delete(store)

        d = adaptor.initialize_store(store)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 0))

        # this should create bob document
        d.addCallback(get_or_create_bob)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))

        d.addCallback(delete_bob)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 0))
        return d

    def test_get_or_create(self):
        adaptor = TestAdaptor()
        store = self._soledad

        def get_or_create_bob(ignored):
            wrapper = CharacterWrapper.get_or_create(
                store, 'by-name', 'bob')
            return wrapper

        d = adaptor.initialize_store(store)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 0))

        # this should create bob document
        d.addCallback(get_or_create_bob)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))

        # this should get us bob document
        d.addCallback(get_or_create_bob)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))
        return d

    def test_get_or_create_multi_index(self):
        adaptor = TestAdaptor()
        store = self._soledad

        def get_or_create_actor_harry(ignored):
            wrapper = ActorWrapper.get_or_create(
                store, 'by-type-and-name', 'harrison')
            return wrapper

        def create_director_harry(ignored):
            wrapper = ActorWrapper(name="harrison", type="director")
            return wrapper.create(store)

        d = adaptor.initialize_store(store)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 0))

        # this should create harrison document
        d.addCallback(get_or_create_actor_harry)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))

        # this should get us harrison document
        d.addCallback(get_or_create_actor_harry)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))

        # create director harry, should create new doc
        d.addCallback(create_director_harry)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 2))

        # this should get us harrison document, still 2 docs
        d.addCallback(get_or_create_actor_harry)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 2))
        return d

    def test_get_all(self):
        adaptor = TestAdaptor()
        store = self._soledad
        actor_names = ["harry", "carrie", "mark", "david"]

        def create_some_actors(ignored):
            deferreds = []
            for name in actor_names:
                dw = ActorWrapper.get_or_create(
                    store, 'by-type-and-name', name)
                deferreds.append(dw)
            return defer.gatherResults(deferreds)

        d = adaptor.initialize_store(store)
        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 0))

        d.addCallback(create_some_actors)

        d.addCallback(lambda _: store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 4))

        def assert_actor_list_is_expected(res):
            got = set([actor.name for actor in res])
            expected = set(actor_names)
            self.assertEqual(got, expected)

        d.addCallback(lambda _: ActorWrapper.get_all(store))
        d.addCallback(assert_actor_list_is_expected)
        return d

HERE = os.path.split(os.path.abspath(__file__))[0]


class TestMessageClass(object):
    def __init__(self, wrapper):
        self.wrapper = wrapper

    def get_wrapper(self):
        return self.wrapper


class SoledadMailAdaptorTestCase(unittest.TestCase, SoledadTestMixin):
    """
    Tests for the SoledadMailAdaptor.
    """

    def get_adaptor(self):
        adaptor = SoledadMailAdaptor()
        adaptor.store = self._soledad
        return adaptor

    def assert_num_docs(self, num, docs):
        self.assertEqual(len(docs[1]), num)

    def test_mail_adaptor_init(self):
        adaptor = self.get_adaptor()
        self.assertTrue(isinstance(adaptor.indexes, dict))
        self.assertTrue(len(adaptor.indexes) != 0)

    # Messages

    def test_get_msg_from_string(self):
        adaptor = self.get_adaptor()

        with open(os.path.join(HERE, "rfc822.message")) as f:
            raw = f.read()

        msg = adaptor.get_msg_from_string(TestMessageClass, raw)

        chash = ("D27B2771C0DCCDCB468EE65A4540438"
                 "09DBD11588E87E951545BE0CBC321C308")
        phash = ("64934534C1C80E0D4FA04BE1CCBA104"
                 "F07BCA5F469C86E2C0ABE1D41310B7299")
        subject = ("[Twisted-commits] rebuild now works on "
                   "python versions from 2.2.0 and up.")
        self.assertTrue(msg.wrapper.fdoc is not None)
        self.assertTrue(msg.wrapper.hdoc is not None)
        self.assertTrue(msg.wrapper.cdocs is not None)
        self.assertEquals(len(msg.wrapper.cdocs), 1)
        self.assertEquals(msg.wrapper.fdoc.chash, chash)
        self.assertEquals(msg.wrapper.fdoc.size, 3834)
        self.assertEquals(msg.wrapper.hdoc.chash, chash)
        self.assertEqual(msg.wrapper.hdoc.headers['subject'],
                         subject)
        self.assertEqual(msg.wrapper.hdoc.subject, subject)
        self.assertEqual(msg.wrapper.cdocs[1].phash, phash)

    def test_get_msg_from_docs(self):
        adaptor = self.get_adaptor()
        mdoc = dict(
            fdoc="F-Foobox-deadbeef",
            hdoc="H-deadbeef",
            cdocs=["C-deadabad"])
        fdoc = dict(
            mbox="Foobox",
            flags=('\Seen', '\Nice'),
            tags=('Personal', 'TODO'),
            seen=False, deleted=False,
            recent=False, multi=False)
        hdoc = dict(
            chash="deadbeef",
            subject="Test Msg")
        cdocs = {
            1: dict(
                raw='This is a test message')}

        msg = adaptor.get_msg_from_docs(
            TestMessageClass, mdoc, fdoc, hdoc, cdocs=cdocs)
        self.assertEqual(msg.wrapper.fdoc.flags,
                         ('\Seen', '\Nice'))
        self.assertEqual(msg.wrapper.fdoc.tags,
                         ('Personal', 'TODO'))
        self.assertEqual(msg.wrapper.fdoc.mbox, "Foobox")
        self.assertEqual(msg.wrapper.hdoc.multi, False)
        self.assertEqual(msg.wrapper.hdoc.subject,
                         "Test Msg")
        self.assertEqual(msg.wrapper.cdocs[1].raw,
                         "This is a test message")

    def test_get_msg_from_metamsg_doc_id(self):
        # XXX complete-me!
        self.fail()

    def test_create_msg(self):
        adaptor = self.get_adaptor()

        with open(os.path.join(HERE, "rfc822.message")) as f:
            raw = f.read()
        msg = adaptor.get_msg_from_string(TestMessageClass, raw)

        def check_create_result(created):
            # that's one mdoc, one hdoc, one fdoc, one cdoc
            self.assertEqual(len(created), 4)
            for doc in created:
                self.assertTrue(
                    doc.__class__.__name__,
                    "SoledadDocument")

        d = adaptor.create_msg(adaptor.store, msg)
        d.addCallback(check_create_result)
        return d

    def test_update_msg(self):
        adaptor = self.get_adaptor()
        with open(os.path.join(HERE, "rfc822.message")) as f:
            raw = f.read()

        def assert_msg_has_doc_id(ignored, msg):
            wrapper = msg.get_wrapper()
            self.assertTrue(wrapper.fdoc.doc_id is not None)

        def assert_msg_has_no_flags(ignored, msg):
            wrapper = msg.get_wrapper()
            self.assertEqual(wrapper.fdoc.flags, [])

        def update_msg_flags(ignored, msg):
            wrapper = msg.get_wrapper()
            wrapper.fdoc.flags = ["This", "That"]
            return wrapper.update(adaptor.store)

        def assert_msg_has_flags(ignored, msg):
            wrapper = msg.get_wrapper()
            self.assertEqual(wrapper.fdoc.flags, ["This", "That"])

        def get_fdoc_and_check_flags(ignored):
            def assert_doc_has_flags(doc):
                self.assertEqual(doc.content['flags'],
                                 ['This', 'That'])
            wrapper = msg.get_wrapper()
            d = adaptor.store.get_doc(wrapper.fdoc.doc_id)
            d.addCallback(assert_doc_has_flags)
            return d

        msg = adaptor.get_msg_from_string(TestMessageClass, raw)
        d = adaptor.create_msg(adaptor.store, msg)
        d.addCallback(lambda _: adaptor.store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 4))
        d.addCallback(assert_msg_has_doc_id, msg)
        d.addCallback(assert_msg_has_no_flags, msg)

        # update it!
        d.addCallback(update_msg_flags, msg)
        d.addCallback(assert_msg_has_flags, msg)
        d.addCallback(get_fdoc_and_check_flags)
        return d

    # Mailboxes

    def test_get_or_create_mbox(self):
        adaptor = self.get_adaptor()

        def get_or_create_mbox(ignored):
            d = adaptor.get_or_create_mbox(adaptor.store, "Trash")
            return d

        def assert_good_doc(mbox_wrapper):
            self.assertTrue(mbox_wrapper.doc_id is not None)
            self.assertEqual(mbox_wrapper.mbox, "Trash")
            self.assertEqual(mbox_wrapper.type, "mbox")
            self.assertEqual(mbox_wrapper.closed, False)
            self.assertEqual(mbox_wrapper.subscribed, False)

        d = adaptor.initialize_store(adaptor.store)
        d.addCallback(get_or_create_mbox)
        d.addCallback(assert_good_doc)
        d.addCallback(lambda _: adaptor.store.get_all_docs())
        d.addCallback(partial(self.assert_num_docs, 1))
        return d

    def test_update_mbox(self):
        adaptor = self.get_adaptor()

        wrapper_ref = []

        def get_or_create_mbox(ignored):
            d = adaptor.get_or_create_mbox(adaptor.store, "Trash")
            return d

        def update_wrapper(wrapper, wrapper_ref):
            wrapper_ref.append(wrapper)
            wrapper.subscribed = True
            wrapper.closed = True
            d = adaptor.update_mbox(adaptor.store, wrapper)
            return d

        def get_mbox_doc_and_check_flags(res, wrapper_ref):
            wrapper = wrapper_ref[0]

            def assert_doc_has_flags(doc):
                self.assertEqual(doc.content['subscribed'], True)
                self.assertEqual(doc.content['closed'], True)
            d = adaptor.store.get_doc(wrapper.doc_id)
            d.addCallback(assert_doc_has_flags)
            return d

        d = adaptor.initialize_store(adaptor.store)
        d.addCallback(get_or_create_mbox)
        d.addCallback(update_wrapper, wrapper_ref)
        d.addCallback(get_mbox_doc_and_check_flags, wrapper_ref)
        return d

    def test_get_all_mboxes(self):
        adaptor = self.get_adaptor()
        mboxes = ("Sent", "Trash", "Personal", "ListFoo")

        def get_or_create_mboxes(ignored):
            d = []
            for mbox in mboxes:
                d.append(adaptor.get_or_create_mbox(
                    adaptor.store, mbox))
            return defer.gatherResults(d)

        def get_all_mboxes(ignored):
            return adaptor.get_all_mboxes(adaptor.store)

        def assert_mboxes_match_expected(wrappers):
            names = [m.mbox for m in wrappers]
            self.assertEqual(set(names), set(mboxes))

        d = adaptor.initialize_store(adaptor.store)
        d.addCallback(get_or_create_mboxes)
        d.addCallback(get_all_mboxes)
        d.addCallback(assert_mboxes_match_expected)
        return d
