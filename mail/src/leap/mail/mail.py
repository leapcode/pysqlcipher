# -*- coding: utf-8 -*-
# mail.py
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
Generic Access to Mail objects: Public LEAP Mail API.
"""
from twisted.internet import defer

from leap.mail.constants import INBOX_NAME
from leap.mail.mailbox_indexer import MailboxIndexer
from leap.mail.adaptors.soledad import SoledadMailAdaptor


# TODO
# [ ] Probably change the name of this module to "api" or "account", mail is
#     too generic (there's also IncomingMail, and OutgoingMail

def _get_mdoc_id(mbox, chash):
    """
    Get the doc_id for the metamsg document.
    """
    return "M+{mbox}+{chash}".format(mbox=mbox, chash=chash)


class Message(object):
    """
    Represents a single message, and gives access to all its attributes.
    """

    def __init__(self, wrapper):
        """
        :param wrapper: an instance of an implementor of IMessageWrapper
        """
        self._wrapper = wrapper

    def get_wrapper(self):
        """
        Get the wrapper for this message.
        """
        return self._wrapper

    # imap.IMessage methods

    def get_flags(self):
        """
        """
        return tuple(self._wrapper.fdoc.flags)

    def get_internal_date(self):
        """
        """
        return self._wrapper.fdoc.date

    # imap.IMessageParts

    def get_headers(self):
        """
        """
        # XXX process here? from imap.messages
        return self._wrapper.hdoc.headers

    def get_body_file(self):
        """
        """

    def get_size(self):
        """
        """
        return self._wrapper.fdoc.size

    def is_multipart(self):
        """
        """
        return self._wrapper.fdoc.multi

    def get_subpart(self, part):
        """
        """
        # XXX ??? return MessagePart?

    # Custom methods.

    def get_tags(self):
        """
        """
        return tuple(self._wrapper.fdoc.tags)


class MessageCollection(object):
    """
    A generic collection of messages. It can be messages sharing the same
    mailbox, tag, the result of a given query, or just a bunch of ids for
    master documents.

    Since LEAP Mail is primarily oriented to store mail in Soledad, the default
    (and, so far, only) implementation of the store is contained in the
    Soledad Mail Adaptor, which is passed to every collection on creation by
    the root Account object. If you need to use a different adaptor, change the
    adaptor class attribute in your Account object.

    Store is a reference to a particular instance of the message store (soledad
    instance or proxy, for instance).
    """

    # TODO
    # [ ] look at IMessageSet methods
    # [ ] make constructor with a per-instance deferredLock to use on
    #     creation/deletion?
    # [ ] instead of a mailbox, we could pass an arbitrary container with
    #     pointers to different doc_ids (type: foo)
    # [ ] To guarantee synchronicity of the documents sent together during a
    #     sync, we could get hold of a deferredLock that inhibits
    #     synchronization while we are updating (think more about this!)

    # Account should provide an adaptor instance when creating this collection.
    adaptor = None
    store = None
    messageklass = Message

    def __init__(self, adaptor, store, mbox_indexer=None, mbox_wrapper=None):
        """
        """
        self.adaptor = adaptor
        self.store = store

        # TODO I have to think about what to do when there is no mbox passed to
        # the initialization. We could still get the MetaMsg by index, instead
        # of by doc_id. See get_message_by_content_hash
        self.mbox_indexer = mbox_indexer
        self.mbox_wrapper = mbox_wrapper

    def is_mailbox_collection(self):
        """
        Return True if this collection represents a Mailbox.
        :rtype: bool
        """
        return bool(self.mbox_wrapper)

    # Get messages

    def get_message_by_content_hash(self, chash, get_cdocs=False):
        """
        Retrieve a message by its content hash.
        :rtype: Deferred
        """

        if not self.is_mailbox_collection():
            # instead of getting the metamsg by chash, query by (meta) index
            # or use the internal collection of pointers-to-docs.
            raise NotImplementedError()

        metamsg_id = _get_mdoc_id(self.mbox_wrapper.mbox, chash)

        return self.adaptor.get_msg_from_mdoc_id(
            self.messageklass, self.store,
            metamsg_id, get_cdocs=get_cdocs)

    def get_message_by_uid(self, uid, absolute=True, get_cdocs=False):
        """
        Retrieve a message by its Unique Identifier.

        If this is a Mailbox collection, that is the message UID, unique for a
        given mailbox, or a relative sequence number depending on the absolute
        flag. For now, only absolute identifiers are supported.
        :rtype: Deferred
        """
        if not absolute:
            raise NotImplementedError("Does not support relative ids yet")

        def get_msg_from_mdoc_id(doc_id):
            return self.adaptor.get_msg_from_mdoc_id(
                self.messageklass, self.store,
                doc_id, get_cdocs=get_cdocs)

        d = self.mbox_indexer.get_doc_id_from_uid(self.mbox_wrapper.mbox, uid)
        d.addCallback(get_msg_from_mdoc_id)
        return d

    def count(self):
        """
        Count the messages in this collection.
        :rtype: int
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()
        return self.mbox_indexer.count(self.mbox_wrapper.mbox)

    # Manipulate messages

    def add_msg(self, raw_msg):
        """
        Add a message to this collection.
        """
        msg = self.adaptor.get_msg_from_string(Message, raw_msg)
        wrapper = msg.get_wrapper()

        if self.is_mailbox_collection():
            mbox = self.mbox_wrapper.mbox
            wrapper.set_mbox(mbox)

        def insert_mdoc_id(_):
            # XXX does this work?
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.insert_doc(
                self.mbox_wrapper.mbox, doc_id)

        d = wrapper.create(self.store)
        d.addCallback(insert_mdoc_id)
        return d

    def copy_msg(self, msg, newmailbox):
        """
        Copy the message to another collection. (it only makes sense for
        mailbox collections)
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()

        def insert_copied_mdoc_id(wrapper):
            return self.mbox_indexer.insert_doc(
                newmailbox, wrapper.mdoc.doc_id)

        wrapper = msg.get_wrapper()
        d = wrapper.copy(self.store, newmailbox)
        d.addCallback(insert_copied_mdoc_id)
        return d

    def delete_msg(self, msg):
        """
        Delete this message.
        """
        wrapper = msg.get_wrapper()

        def delete_mdoc_id(_):
            # XXX does this work?
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.delete_doc_by_hash(
                self.mbox_wrapper.mbox, doc_id)
        d = wrapper.delete(self.store)
        d.addCallback(delete_mdoc_id)
        return d

    # TODO should add a delete-by-uid to collection?

    def udpate_flags(self, msg, flags, mode):
        """
        Update flags for a given message.
        """
        wrapper = msg.get_wrapper()
        # 1. update the flags in the message wrapper --- stored where???
        # 2. update the special flags in the wrapper (seen, etc)
        # 3. call adaptor.update_msg(store)
        pass

    def update_tags(self, msg, tags, mode):
        """
        Update tags for a given message.
        """
        wrapper = msg.get_wrapper()
        # 1. update the tags in the message wrapper --- stored where???
        # 2. call adaptor.update_msg(store)
        pass


class Account(object):
    """
    Account is the top level abstraction to access collections of messages
    associated with a LEAP Mail Account.

    It primarily handles creation and access of Mailboxes, which will be the
    basic collection handled by traditional MUAs, but it can also handle other
    types of Collections (tag based, for instance).

    leap.mail.imap.SoledadBackedAccount partially proxies methods in this
    class.
    """

    # Adaptor is passed to the returned MessageCollections, so if you want to
    # use a different adaptor this is the place to change it, by subclassing
    # the Account class.

    adaptor_class = SoledadMailAdaptor
    store = None
    mailboxes = None

    def __init__(self, store):
        self.store = store
        self.adaptor = self.adaptor_class()
        self.mbox_indexer = MailboxIndexer(self.store)

        self._initialized = False
        self._deferred_initialization = defer.Deferred()

        self._initialize_storage()

    def _initialize_storage(self):

        def add_mailbox_if_none(mboxes):
            if not mboxes:
                self.add_mailbox(INBOX_NAME)

        def finish_initialization(result):
            self._initialized = True
            self._deferred_initialization.callback(None)

        d = self.adaptor.initialize_store(self.store)
        d.addCallback(self.list_all_mailbox_names)
        d.addCallback(add_mailbox_if_none)
        d.addCallback(finish_initialization)

    def callWhenReady(self, cb):
        # XXX this could use adaptor.store_ready instead...??
        if self._initialized:
            cb(self)
            return defer.succeed(None)
        else:
            self._deferred_initialization.addCallback(cb)
            return self._deferred_initialization

    #
    # Public API Starts
    #

    def list_all_mailbox_names(self):
        def filter_names(mboxes):
            return [m.name for m in mboxes]

        d = self.get_all_mailboxes()
        d.addCallback(filter_names)
        return d

    def get_all_mailboxes(self):
        d = self.adaptor.get_all_mboxes(self.store)
        return d

    def add_mailbox(self, name):

        def create_uid_table_cb(res):
            d = self.mbox_uid.create_table(name)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.__class__.get_or_create(name)
        d.addCallback(create_uid_table_cb)
        return d

    def delete_mailbox(self, name):
        def delete_uid_table_cb(res):
            d = self.mbox_uid.delete_table(name)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.delete_mbox(self.store)
        d.addCallback(delete_uid_table_cb)
        return d

    def rename_mailbox(self, oldname, newname):
        def _rename_mbox(wrapper):
            wrapper.mbox = newname
            return wrapper.update()

        def rename_uid_table_cb(res):
            d = self.mbox_uid.rename_table(oldname, newname)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.__class__.get_or_create(oldname)
        d.addCallback(_rename_mbox)
        d.addCallback(rename_uid_table_cb)
        return d

    def get_collection_by_mailbox(self, name):
        """
        :rtype: MessageCollection
        """
        # imap select will use this, passing the collection to SoledadMailbox
        def get_collection_for_mailbox(mbox_wrapper):
            return MessageCollection(
                self.adaptor, self.store, self.mbox_indexer, mbox_wrapper)

        mboxwrapper_klass = self.adaptor.mboxwrapper_klass
        d = mboxwrapper_klass.get_or_create(name)
        d.addCallback(get_collection_for_mailbox)
        return d

    def get_collection_by_docs(self, docs):
        """
        :rtype: MessageCollection
        """
        # get a collection of docs by a list of doc_id
        # get.docs(...) --> it should be a generator. does it behave in the
        # threadpool?
        raise NotImplementedError()

    def get_collection_by_tag(self, tag):
        """
        :rtype: MessageCollection
        """
        raise NotImplementedError()
