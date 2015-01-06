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
import logging
import StringIO

from twisted.internet import defer

from leap.common.check import leap_assert_type
from leap.common.mail import get_email_charset

from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.constants import INBOX_NAME
from leap.mail.constants import MessageFlags
from leap.mail.mailbox_indexer import MailboxIndexer
from leap.mail.utils import empty, find_charset

logger = logging.getLogger(name=__name__)


# TODO LIST
# [ ] Probably change the name of this module to "api" or "account", mail is
#     too generic (there's also IncomingMail, and OutgoingMail
# [ ] Change the doc_ids scheme for part-docs: use mailbox UID validity
#     identifier, instead of name! (renames are broken!)
# [ ] Profile add_msg.

def _get_mdoc_id(mbox, chash):
    """
    Get the doc_id for the metamsg document.
    """
    return "M+{mbox}+{chash}".format(mbox=mbox, chash=chash)


def _write_and_rewind(payload):
    fd = StringIO.StringIO()
    fd.write(payload)
    fd.seek(0)
    return fd


class MessagePart(object):

    # TODO pass cdocs in init

    def __init__(self, part_map, cdocs={}):
        self._pmap = part_map
        self._cdocs = cdocs

    def get_size(self):
        return self._pmap['size']

    def get_body_file(self):
        pmap = self._pmap
        multi = pmap.get('multi')
        if not multi:
            phash = pmap.get("phash")
        else:
            pmap_ = pmap.get('part_map')
            first_part = pmap_.get('1', None)
            if not empty(first_part):
                phash = first_part['phash']
            else:
                phash = ""

        payload = self._get_payload(phash)

        if payload:
            # FIXME
            # content_type = self._get_ctype_from_document(phash)
            # charset = find_charset(content_type)
            charset = None
            if charset is None:
                charset = get_email_charset(payload)
            try:
                if isinstance(payload, unicode):
                    payload = payload.encode(charset)
            except UnicodeError as exc:
                logger.error(
                    "Unicode error, using 'replace'. {0!r}".format(exc))
                payload = payload.encode(charset, 'replace')

        return _write_and_rewind(payload)

    def get_headers(self):
        return self._pmap.get("headers", [])

    def is_multipart(self):
        multi = self._pmap.get("multi", False)
        return multi

    def get_subpart(self, part):
        if not self.is_multipart():
            raise TypeError

        sub_pmap = self._pmap.get("part_map", {})
        try:
            part_map = sub_pmap[str(part + 1)]
        except KeyError:
            logger.debug("getSubpart for %s: KeyError" % (part,))
            raise IndexError
        return MessagePart(self._soledad, part_map)

    def _get_payload(self, phash):
        return self._cdocs.get(phash, "")


class Message(object):
    """
    Represents a single message, and gives access to all its attributes.
    """

    def __init__(self, wrapper, uid=None):
        """
        :param wrapper: an instance of an implementor of IMessageWrapper
        :param uid:
        :type uid: int
        """
        self._wrapper = wrapper
        self._uid = uid

    def get_wrapper(self):
        """
        Get the wrapper for this message.
        """
        return self._wrapper

    def get_uid(self):
        """
        Get the (optional) UID.
        """
        return self._uid

    # imap.IMessage methods

    def get_flags(self):
        """
        Get flags for this message.
        :rtype: tuple
        """
        return tuple(self._wrapper.fdoc.flags)

    def get_internal_date(self):
        """
        Retrieve the date internally associated with this message

        According to the spec, this is NOT the date and time in the
        RFC-822 header, but rather a date and time that reflects when the
        message was received.

        * In SMTP, date and time of final delivery.
        * In COPY, internal date/time of the source message.
        * In APPEND, date/time specified.

        :return: An RFC822-formatted date string.
        :rtype: str
        """
        return self._wrapper.fdoc.date

    # imap.IMessageParts

    def get_headers(self):
        """
        Get the raw headers document.
        """
        return [tuple(item) for item in self._wrapper.hdoc.headers]

    def get_body_file(self, store):
        """
        """
        def write_and_rewind_if_found(cdoc):
            if not cdoc:
                return None
            return _write_and_rewind(cdoc.raw)

        d = defer.maybeDeferred(self._wrapper.get_body, store)
        d.addCallback(write_and_rewind_if_found)
        return d

    def get_size(self):
        """
        Size, in octets.
        """
        return self._wrapper.fdoc.size

    def is_multipart(self):
        """
        Return True if this message is multipart.
        """
        return self._wrapper.fdoc.multi

    def get_subpart(self, part):
        """
        :param part: The number of the part to retrieve, indexed from 0.
        :type part: int
        :rtype: MessagePart
        """
        if not self.is_multipart():
            raise TypeError
        part_index = part + 1
        try:
            subpart_dict = self._wrapper.get_subpart_dict(
                part_index)
        except KeyError:
            raise TypeError
        # XXX pass cdocs
        return MessagePart(subpart_dict)

    # Custom methods.

    def get_tags(self):
        """
        """
        return tuple(self._wrapper.fdoc.tags)


class Flagsmode(object):
    """
    Modes for setting the flags/tags.
    """
    APPEND = 1
    REMOVE = -1
    SET = 0


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

    # TODO LIST
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
        Constructore for a MessageCollection.
        """
        self.adaptor = adaptor
        self.store = store

        # XXX I have to think about what to do when there is no mbox passed to
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

    @property
    def mbox_name(self):
        wrapper = getattr(self, "mbox_wrapper", None)
        if not wrapper:
            return None
        return wrapper.mbox

    def get_mbox_attr(self, attr):
        return getattr(self.mbox_wrapper, attr)

    def set_mbox_attr(self, attr, value):
        setattr(self.mbox_wrapper, attr, value)
        return self.mbox_wrapper.update(self.store)

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

        metamsg_id = _get_mdoc_id(self.mbox_name, chash)

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
            if doc_id is None:
                return None
            return self.adaptor.get_msg_from_mdoc_id(
                self.messageklass, self.store,
                doc_id, uid=uid, get_cdocs=get_cdocs)

        d = self.mbox_indexer.get_doc_id_from_uid(self.mbox_name, uid)
        d.addCallback(get_msg_from_mdoc_id)
        return d

    def count(self):
        """
        Count the messages in this collection.
        :return: a Deferred that will fire with the integer for the count.
        :rtype: Deferred
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()
        return self.mbox_indexer.count(self.mbox_name)

    def get_uid_next(self):
        """
        Get the next integer beyond the highest UID count for this mailbox.

        :return: a Deferred that will fire with the integer for the next uid.
        :rtype: Deferred
        """
        return self.mbox_indexer.get_next_uid(self.mbox_name)

    # Manipulate messages

    def add_msg(self, raw_msg, flags=None, tags=None, date=None):
        """
        Add a message to this collection.
        """
        if not flags:
            flags = tuple()
        if not tags:
            tags = tuple()
        leap_assert_type(flags, tuple)
        leap_assert_type(date, str)

        msg = self.adaptor.get_msg_from_string(Message, raw_msg)
        wrapper = msg.get_wrapper()

        if not self.is_mailbox_collection():
            raise NotImplementedError()

        else:
            mbox = self.mbox_name
            wrapper.set_flags(flags)
            wrapper.set_tags(tags)
            wrapper.set_date(date)
            wrapper.set_mbox(mbox)

        def insert_mdoc_id(_, wrapper):
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.insert_doc(
                self.mbox_name, doc_id)

        d = wrapper.create(self.store)
        d.addCallback(insert_mdoc_id, wrapper)
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

        def delete_mdoc_id(_, wrapper):
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.delete_doc_by_hash(
                self.mbox_name, doc_id)
        d = wrapper.delete(self.store)
        d.addCallback(delete_mdoc_id, wrapper)
        return d

    # TODO should add a delete-by-uid to collection?

    def _update_flags_or_tags(self, old, new, mode):
        if mode == Flagsmode.APPEND:
            final = list((set(tuple(old) + new)))
        elif mode == Flagsmode.REMOVE:
            final = list(set(old).difference(set(new)))
        elif mode == Flagsmode.SET:
            final = new
        return final

    def udpate_flags(self, msg, flags, mode):
        """
        Update flags for a given message.
        """
        wrapper = msg.get_wrapper()
        current = wrapper.fdoc.flags
        newflags = self._update_flags_or_tags(current, flags, mode)
        wrapper.fdoc.flags = newflags

        wrapper.fdoc.seen = MessageFlags.SEEN_FLAG in newflags
        wrapper.fdoc.deleted = MessageFlags.DELETED_FLAG in newflags

        return self.adaptor.update_msg(self.store, msg)

    def update_tags(self, msg, tags, mode):
        """
        Update tags for a given message.
        """
        wrapper = msg.get_wrapper()
        current = wrapper.fdoc.tags
        newtags = self._update_flags_or_tags(current, tags, mode)
        wrapper.fdoc.tags = newtags
        return self.adaptor.update_msg(self.store, msg)


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
        d.addCallback(lambda _: self.list_all_mailbox_names())
        d.addCallback(add_mailbox_if_none)
        d.addCallback(finish_initialization)

    def callWhenReady(self, cb, *args, **kw):
        # use adaptor.store_ready instead?
        if self._initialized:
            cb(self, *args, **kw)
            return defer.succeed(None)
        else:
            self._deferred_initialization.addCallback(cb, *args, **kw)
            return self._deferred_initialization

    #
    # Public API Starts
    #

    def list_all_mailbox_names(self):
        def filter_names(mboxes):
            return [m.mbox for m in mboxes]

        d = self.get_all_mailboxes()
        d.addCallback(filter_names)
        return d

    def get_all_mailboxes(self):
        d = self.adaptor.get_all_mboxes(self.store)
        return d

    def add_mailbox(self, name):

        def create_uid_table_cb(res):
            d = self.mbox_indexer.create_table(name)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, name)
        d.addCallback(create_uid_table_cb)
        return d

    def delete_mailbox(self, name):
        def delete_uid_table_cb(res):
            d = self.mbox_indexer.delete_table(name)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, name)
        d.addCallback(
            lambda wrapper: self.adaptor.delete_mbox(self.store, wrapper))
        d.addCallback(delete_uid_table_cb)
        return d

    def rename_mailbox(self, oldname, newname):
        # TODO incomplete/wrong!!!
        # Should rename also ALL of the document ids that are pointing
        # to the old mailbox!!!

        # TODO part-docs identifiers should have the UID_validity of the
        # mailbox embedded, instead of the name! (so they can survive a rename)

        def _rename_mbox(wrapper):
            wrapper.mbox = newname
            return wrapper.update(self.store)

        def rename_uid_table_cb(res):
            d = self.mbox_indexer.rename_table(oldname, newname)
            d.addCallback(lambda _: res)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, oldname)
        d.addCallback(_rename_mbox)
        d.addCallback(rename_uid_table_cb)
        return d

    # Get Collections

    def get_collection_by_mailbox(self, name):
        """
        :rtype: MessageCollection
        """
        # imap select will use this, passing the collection to SoledadMailbox
        def get_collection_for_mailbox(mbox_wrapper):
            return MessageCollection(
                self.adaptor, self.store, self.mbox_indexer, mbox_wrapper)

        mboxwrapper_klass = self.adaptor.mboxwrapper_klass
        #d = mboxwrapper_klass.get_or_create(name)
        d = self.adaptor.get_or_create_mbox(self.store, name)
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
