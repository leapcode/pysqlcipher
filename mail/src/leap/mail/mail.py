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
import uuid
import logging
import StringIO
import cStringIO
import time

from email.utils import formatdate
from twisted.internet import defer

from leap.common.check import leap_assert_type
from leap.common.mail import get_email_charset

from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.constants import INBOX_NAME
from leap.mail.constants import MessageFlags
from leap.mail.mailbox_indexer import MailboxIndexer

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
    # TODO This class should be better abstracted from the data model.
    # TODO support arbitrarily nested multiparts (right now we only support
    #      the trivial case)

    def __init__(self, part_map, cdocs={}):
        """
        :param part_map: a dictionary mapping the subparts for
                         this MessagePart (1-indexed).
        :type part_map: dict

        The format for the part_map is as follows:

        {u'ctype': u'text/plain',
        u'headers': [[u'Content-Type', u'text/plain; charset="utf-8"'],
                     [u'Content-Transfer-Encoding', u'8bit']],
        u'multi': False,
        u'parts': 1,
        u'phash': u'02D82B29F6BB0C8612D1C',
        u'size': 132}

        :param cdocs: optional, a reference to the top-level dict of wrappers
                      for content-docs (1-indexed).
        """
        self._pmap = part_map
        self._cdocs = cdocs

        index = 1
        phash = part_map.get('phash', None)
        if phash:
            for i, cdoc_wrapper in self._cdocs.items():
                if cdoc_wrapper.phash == phash:
                    index = i
                    break
        self._index = index

    def get_size(self):
        return self._pmap['size']

    def get_body_file(self):
        payload = ""
        pmap = self._pmap
        multi = pmap.get('multi')
        if not multi:
            payload = self._get_payload(self._index)
        else:
            # XXX uh, multi also...  should recurse"
            raise NotImplementedError
        if payload:
            payload = self._format_payload(payload)
        return _write_and_rewind(payload)

    def get_headers(self):
        return self._pmap.get("headers", [])

    def is_multipart(self):
        return self._pmap.get("multi", False)

    def get_subpart(self, part):
        if not self.is_multipart():
            raise TypeError

        sub_pmap = self._pmap.get("part_map", {})
        try:
            part_map = sub_pmap[str(part + 1)]
        except KeyError:
            logger.debug("getSubpart for %s: KeyError" % (part,))
            raise IndexError
        return MessagePart(part_map, cdocs={1: self._cdocs.get(part + 1, {})})

    def _get_payload(self, index):
        cdoc_wrapper = self._cdocs.get(index, None)
        if cdoc_wrapper:
            return cdoc_wrapper.raw
        return ""

    def _format_payload(self, payload):
        # FIXME -----------------------------------------------
        # Test against unicode payloads...
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
        return payload


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
        return self._wrapper.fdoc.get_flags()

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
        return self._wrapper.hdoc.date

    # imap.IMessageParts

    def get_headers(self):
        """
        Get the raw headers document.
        """
        return [tuple(item) for item in self._wrapper.hdoc.headers]

    def get_body_file(self, store):
        """
        Get a file descriptor with the body content.
        """
        def write_and_rewind_if_found(cdoc):
            payload = cdoc.raw if cdoc else ""
            return _write_and_rewind(payload)

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
            subpart_dict = self._wrapper.get_subpart_dict(part_index)
        except KeyError:
            raise IndexError

        # FIXME instead of passing the index, let the MessagePart figure it out
        # by getting the phash and iterating through the cdocs
        return MessagePart(
            subpart_dict, cdocs=self._wrapper.cdocs)

    # Custom methods.

    def get_tags(self):
        """
        Get the tags for this message.
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
    # [ ] review the serveral count_ methods. I think it's better to patch
    #     server to accept deferreds.
    # [ ] Use inheritance for the mailbox-collection instead of handling the
    #     special cases everywhere?
    # [ ] or maybe a mailbox_only decorator...

    # Account should provide an adaptor instance when creating this collection.
    adaptor = None
    store = None
    messageklass = Message

    def __init__(self, adaptor, store, mbox_indexer=None, mbox_wrapper=None):
        """
        Constructor for a MessageCollection.
        """
        self.adaptor = adaptor
        self.store = store

        # XXX think about what to do when there is no mbox passed to
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
        # TODO raise instead?
        if self.mbox_wrapper is None:
            return None
        return self.mbox_wrapper.mbox

    @property
    def mbox_uuid(self):
        # TODO raise instead?
        if self.mbox_wrapper is None:
            return None
        return self.mbox_wrapper.uuid

    def get_mbox_attr(self, attr):
        if self.mbox_wrapper is None:
            raise RuntimeError("This is not a mailbox collection")
        return getattr(self.mbox_wrapper, attr)

    def set_mbox_attr(self, attr, value):
        if self.mbox_wrapper is None:
            raise RuntimeError("This is not a mailbox collection")
        setattr(self.mbox_wrapper, attr, value)
        return self.mbox_wrapper.update(self.store)

    # Get messages

    def get_message_by_content_hash(self, chash, get_cdocs=False):
        """
        Retrieve a message by its content hash.
        :rtype: Deferred
        """
        if not self.is_mailbox_collection():
            # TODO instead of getting the metamsg by chash, in this case we
            # should query by (meta) index or use the internal collection of
            # pointers-to-docs.
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

        d = self.mbox_indexer.get_doc_id_from_uid(self.mbox_uuid, uid)
        d.addCallback(get_msg_from_mdoc_id)
        return d

    def get_flags_by_uid(self, uid, absolute=True):
        if not absolute:
            raise NotImplementedError("Does not support relative ids yet")

        def get_flags_from_mdoc_id(doc_id):
            if doc_id is None:  # XXX needed? or bug?
                return None
            return self.adaptor.get_flags_from_mdoc_id(
                self.store, doc_id)

        def wrap_in_tuple(flags):
            return (uid, flags)

        d = self.mbox_indexer.get_doc_id_from_uid(self.mbox_uuid, uid)
        d.addCallback(get_flags_from_mdoc_id)
        d.addCallback(wrap_in_tuple)
        return d

    def count(self):
        """
        Count the messages in this collection.
        :return: a Deferred that will fire with the integer for the count.
        :rtype: Deferred
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()

        d = self.mbox_indexer.count(self.mbox_uuid)
        return d

    def count_recent(self):
        """
        Count the recent messages in this collection.
        :return: a Deferred that will fire with the integer for the count.
        :rtype: Deferred
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()
        return self.adaptor.get_count_recent(self.store, self.mbox_uuid)

    def count_unseen(self):
        """
        Count the unseen messages in this collection.
        :return: a Deferred that will fire with the integer for the count.
        :rtype: Deferred
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()
        return self.adaptor.get_count_unseen(self.store, self.mbox_uuid)

    def get_uid_next(self):
        """
        Get the next integer beyond the highest UID count for this mailbox.

        :return: a Deferred that will fire with the integer for the next uid.
        :rtype: Deferred
        """
        return self.mbox_indexer.get_next_uid(self.mbox_uuid)

    def get_last_uid(self):
        """
        Get the last UID for this mailbox.
        """
        return self.mbox_indexer.get_last_uid(self.mbox_uuid)

    def all_uid_iter(self):
        """
        Iterator through all the uids for this collection.
        """
        return self.mbox_indexer.all_uid_iter(self.mbox_uuid)

    def get_uid_from_msgid(self, msgid):
        """
        Return the UID(s) of the matching msg-ids for this mailbox collection.
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()

        def get_uid(mdoc_id):
            if not mdoc_id:
                return None
            d = self.mbox_indexer.get_uid_from_doc_id(
                self.mbox_uuid, mdoc_id)
            return d

        d = self.adaptor.get_mdoc_id_from_msgid(
            self.store, self.mbox_uuid, msgid)
        d.addCallback(get_uid)
        return d

    # Manipulate messages

    def add_msg(self, raw_msg, flags=tuple(), tags=tuple(), date="",
                notify_just_mdoc=False):
        """
        Add a message to this collection.

        :param notify_just_mdoc:
            boolean passed to the wrapper.create method,
            to indicate whether we're interested in being notified when only
            the mdoc has been written (faster, but potentially unsafe), or we
            want to wait untill all the parts have been written.
            Used by the imap mailbox implementation to get faster responses.
        :type notify_just_mdoc: bool

        :returns: a deferred that will fire with the UID of the inserted
                  message.
        :rtype: deferred
        """
        # XXX mdoc ref is a leaky abstraction here. generalize.
        leap_assert_type(flags, tuple)
        leap_assert_type(date, str)

        msg = self.adaptor.get_msg_from_string(Message, raw_msg)
        wrapper = msg.get_wrapper()

        if not self.is_mailbox_collection():
            raise NotImplementedError()

        else:
            mbox_id = self.mbox_uuid
            wrapper.set_mbox_uuid(mbox_id)
            wrapper.set_flags(flags)
            wrapper.set_tags(tags)
            wrapper.set_date(date)

        def insert_mdoc_id(_, wrapper):
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.insert_doc(
                self.mbox_uuid, doc_id)

        d = wrapper.create(self.store, notify_just_mdoc=notify_just_mdoc)
        d.addCallback(insert_mdoc_id, wrapper)
        d.addErrback(lambda f: f.printTraceback())
        return d

    def add_raw_message(self, message, flags, date=None):
        """
        Adds a message to this collection.

        :param message: the raw message
        :type message: str

        :param flags: flag list
        :type flags: list of str

        :param date: timestamp
        :type date: str

        :return: a deferred that will be triggered with the UID of the added
                 message.
        """
        # TODO should raise ReadOnlyMailbox if not rw.
        # TODO have a look at the cases for internal date in the rfc
        if isinstance(message, (cStringIO.OutputType, StringIO.StringIO)):
            message = message.getvalue()

        # XXX we could treat the message as an IMessage from here
        leap_assert_type(message, basestring)

        if flags is None:
            flags = tuple()
        else:
            flags = tuple(str(flag) for flag in flags)

        if date is None:
            date = formatdate(time.time())

        # A better place for this would be  the COPY/APPEND dispatcher
        # if PROFILE_CMD:
        # do_profile_cmd(d, "APPEND")

        # just_mdoc=True: feels HACKY, but improves a *lot* the responsiveness
        # of the APPENDS: we just need to be notified when the mdoc
        # is saved, and let's hope that the other parts are doing just fine.
        # This will not catch any errors when the inserts of the other parts
        # fail, but on the other hand allows us to return very quickly, which
        # seems a good compromise given that we have to serialize the appends.
        # A better solution will probably involve implementing MULTIAPPEND
        # or patching imap server to support pipelining.

        d = self.add_msg(message, flags=flags, date=date,
                         notify_just_mdoc=True)
        d.addErrback(lambda f: logger.warning(f.getTraceback()))
        return d

    def copy_msg(self, msg, new_mbox_uuid):
        """
        Copy the message to another collection. (it only makes sense for
        mailbox collections)
        """
        if not self.is_mailbox_collection():
            raise NotImplementedError()

        def insert_copied_mdoc_id(wrapper_new_msg):
            return self.mbox_indexer.insert_doc(
                new_mbox_uuid, wrapper_new_msg.mdoc.doc_id)

        wrapper = msg.get_wrapper()

        d = wrapper.copy(self.store, new_mbox_uuid)
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

    def delete_all_flagged(self):
        """
        Delete all messages flagged as \\Deleted.
        Used from IMAPMailbox.expunge()
        """
        def get_uid_list(hashes):
            d = []
            for h in hashes:
                d.append(self.mbox_indexer.get_uid_from_doc_id(
                         self.mbox_uuid, h))
            return defer.gatherResults(d), hashes

        def delete_uid_entries((uids, hashes)):
            d = []
            for h in hashes:
                d.append(self.mbox_indexer.delete_doc_by_hash(
                         self.mbox_uuid, h))
            return defer.gatherResults(d).addCallback(
                lambda _: uids)

        mdocs_deleted = self.adaptor.del_all_flagged_messages(
            self.store, self.mbox_uuid)
        mdocs_deleted.addCallback(get_uid_list)
        mdocs_deleted.addCallback(delete_uid_entries)
        return mdocs_deleted

    # TODO should add a delete-by-uid to collection?

    def delete_all_docs(self):
        def del_all_uid(uid_list):
            deferreds = []
            for uid in uid_list:
                d = self.get_message_by_uid(uid)
                d.addCallback(lambda msg: msg.delete())
                deferreds.append(d)
            return defer.gatherResults(deferreds)

        d = self.all_uid_iter()
        d.addCallback(del_all_uid)
        return d

    def update_flags(self, msg, flags, mode):
        """
        Update flags for a given message.
        """
        wrapper = msg.get_wrapper()
        current = wrapper.fdoc.flags
        newflags = map(str, self._update_flags_or_tags(current, flags, mode))
        wrapper.fdoc.flags = newflags

        wrapper.fdoc.seen = MessageFlags.SEEN_FLAG in newflags
        wrapper.fdoc.deleted = MessageFlags.DELETED_FLAG in newflags

        d = self.adaptor.update_msg(self.store, msg)
        d.addCallback(lambda _: newflags)
        return d

    def update_tags(self, msg, tags, mode):
        """
        Update tags for a given message.
        """
        wrapper = msg.get_wrapper()
        current = wrapper.fdoc.tags
        newtags = self._update_flags_or_tags(current, tags, mode)

        wrapper.fdoc.tags = newtags
        d = self.adaptor.update_msg(self.store, msg)
        d.addCallback(newtags)
        return d

    def _update_flags_or_tags(self, old, new, mode):
        if mode == Flagsmode.APPEND:
            final = list((set(tuple(old) + new)))
        elif mode == Flagsmode.REMOVE:
            final = list(set(old).difference(set(new)))
        elif mode == Flagsmode.SET:
            final = new
        return final


class Account(object):
    """
    Account is the top level abstraction to access collections of messages
    associated with a LEAP Mail Account.

    It primarily handles creation and access of Mailboxes, which will be the
    basic collection handled by traditional MUAs, but it can also handle other
    types of Collections (tag based, for instance).

    leap.mail.imap.IMAPAccount partially proxies methods in this
    class.
    """

    # Adaptor is passed to the returned MessageCollections, so if you want to
    # use a different adaptor this is the place to change it, by subclassing
    # the Account class.

    adaptor_class = SoledadMailAdaptor

    def __init__(self, store, ready_cb=None):
        self.store = store
        self.adaptor = self.adaptor_class()
        self.mbox_indexer = MailboxIndexer(self.store)

        self.deferred_initialization = defer.Deferred()
        self._ready_cb = ready_cb

        self._init_d = self._initialize_storage()

    def _initialize_storage(self):

        def add_mailbox_if_none(mboxes):
            if not mboxes:
                return self.add_mailbox(INBOX_NAME)

        def finish_initialization(result):
            self.deferred_initialization.callback(None)
            if self._ready_cb is not None:
                self._ready_cb()

        d = self.adaptor.initialize_store(self.store)
        d.addCallback(lambda _: self.list_all_mailbox_names())
        d.addCallback(add_mailbox_if_none)
        d.addCallback(finish_initialization)
        return d

    def callWhenReady(self, cb, *args, **kw):
        """
        Execute the callback when the initialization of the Account is ready.
        Note that the callback will receive a first meaningless parameter.
        """
        # TODO this should ignore the first parameter explicitely
        # lambda _: cb(*args, **kw)
        self.deferred_initialization.addCallback(cb, *args, **kw)
        return self.deferred_initialization

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

        def create_uuid(wrapper):
            if not wrapper.uuid:
                wrapper.uuid = str(uuid.uuid4())
                d = wrapper.update(self.store)
                d.addCallback(lambda _: wrapper)
                return d
            return wrapper

        def create_uid_table_cb(wrapper):
            d = self.mbox_indexer.create_table(wrapper.uuid)
            d.addCallback(lambda _: wrapper)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, name)
        d.addCallback(create_uuid)
        d.addCallback(create_uid_table_cb)
        return d

    def delete_mailbox(self, name):

        def delete_uid_table_cb(wrapper):
            d = self.mbox_indexer.delete_table(wrapper.uuid)
            d.addCallback(lambda _: wrapper)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, name)
        d.addCallback(delete_uid_table_cb)
        d.addCallback(
            lambda wrapper: self.adaptor.delete_mbox(self.store, wrapper))
        return d

    def rename_mailbox(self, oldname, newname):
        # TODO incomplete/wrong!!!
        # Should rename also ALL of the document ids that are pointing
        # to the old mailbox!!!

        # TODO part-docs identifiers should have the UID_validity of the
        # mailbox embedded, instead of the name! (so they can survive a rename)

        def _rename_mbox(wrapper):
            wrapper.mbox = newname
            return wrapper, wrapper.update(self.store)

        d = self.adaptor.get_or_create_mbox(self.store, oldname)
        d.addCallback(_rename_mbox)
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
