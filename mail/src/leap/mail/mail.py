# -*- coding: utf-8 -*-
# mail.py
# Copyright (C) 2014,2015 LEAP
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
Generic Access to Mail objects.

This module holds the public LEAP Mail API, which should be viewed as the main
entry point for message and account manipulation, in a protocol-agnostic way.

In the future, pluggable transports will expose this generic API.
"""
import itertools
import uuid
import logging
import StringIO
import time
import weakref

from collections import defaultdict

from twisted.internet import defer
from twisted.python import log

from leap.common.check import leap_assert_type
from leap.common.events import emit_async, catalog
from leap.common.mail import get_email_charset

from leap.mail.adaptors.soledad import SoledadMailAdaptor
from leap.mail.constants import INBOX_NAME
from leap.mail.constants import MessageFlags
from leap.mail.mailbox_indexer import MailboxIndexer
from leap.mail.plugins import soledad_sync_hooks
from leap.mail.utils import find_charset, CaseInsensitiveDict
from leap.mail.utils import lowerdict

logger = logging.getLogger(name=__name__)


# TODO LIST
# [ ] Probably change the name of this module to "api" or "account", mail is
#     too generic (there's also IncomingMail, and OutgoingMail
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


def _encode_payload(payload, ctype=""):
    """
    Properly encode an unicode payload (which can be string or unicode) as a
    string.

    :param payload: the payload to encode. currently soledad returns unicode
                    strings.
    :type payload: basestring
    :param ctype: optional, the content of the content-type header for this
                  payload.
    :type ctype: str
    :rtype: str
    """
    # TODO Related, it's proposed that we're able to pass
    # the encoding to the soledad documents. Better to store the charset there?
    # FIXME -----------------------------------------------
    # this need a dedicated test-suite
    charset = find_charset(ctype)

    # XXX get from mail headers if not multipart!
    # Beware also that we should pass the proper encoding to
    # soledad when it's creating the documents.
    # if not charset:
    # charset = get_email_charset(payload)
    # -----------------------------------------------------

    if not charset:
        charset = "utf-8"

    try:
        if isinstance(payload, unicode):
            payload = payload.encode(charset)
    except UnicodeError as exc:
        logger.error(
            "Unicode error, using 'replace'. {0!r}".format(exc))
        payload = payload.encode(charset, 'replace')
    return payload


def _unpack_headers(headers_dict):
    """
    Take a "packed" dict containing headers (with repeated keys represented as
    line breaks inside each value, preceded by the header key) and return a
    list of tuples in which each repeated key has a different tuple.
    """
    headers_l = headers_dict.items()
    for i, (k, v) in enumerate(headers_l):
        splitted = v.split(k.lower() + ": ")
        if len(splitted) != 1:
            inner = zip(
                itertools.cycle([k]),
                map(lambda l: l.rstrip('\n'), splitted))
            headers_l = headers_l[:i] + inner + headers_l[i + 1:]
    return headers_l


def _get_index_for_cdoc(part_map, cdocs_dict):
    """
    Get, if possible, the index for a given content-document matching the phash
    of the passed part_map.

    This is used when we are initializing a MessagePart, because we just pass a
    reference to the parent message cdocs container and we need to iterate
    through the cdocs to figure out which content-doc matches the phash of the
    part we're currently rendering.

    It is also used when recursing through a nested multipart message, because
    in the initialization of the child MessagePart we pass a dictionary only
    for the referenced cdoc.

    :param part_map: a dict describing the mapping of the parts for the current
                     message-part.
    :param cdocs: a dict of content-documents, 0-indexed.
    :rtype: int
    """
    phash = part_map.get('phash', None)
    if phash:
        for i, cdoc_wrapper in cdocs_dict.items():
            if cdoc_wrapper.phash == phash:
                return i
    return None


class MessagePart(object):
    # TODO This class should be better abstracted from the data model.
    # TODO support arbitrarily nested multiparts (right now we only support
    #      the trivial case)
    """
    Represents a part of a multipart MIME Message.
    """

    def __init__(self, part_map, cdocs={}, nested=False):
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
        self._nested = nested

        index = _get_index_for_cdoc(part_map, self._cdocs) or 1
        self._index = index

    def get_size(self):
        """
        Size of the body, in octets.
        """
        total = self._pmap['size']
        _h = self.get_headers()
        headers = len(
            '\n'.join(["%s: %s" % (k, v) for k, v in dict(_h).items()]))
        # have to subtract 2 blank lines
        return total - headers - 2

    def get_body_file(self):
        payload = ""
        pmap = self._pmap
        multi = pmap.get('multi')
        if not multi:
            payload = self._get_payload(self._index)
        else:
            # XXX uh, multi also...  should recurse.
            # This needs to be implemented in a more general and elegant way.
            raise NotImplementedError
        if payload:
            payload = _encode_payload(payload)

        return _write_and_rewind(payload)

    def get_headers(self):
        return CaseInsensitiveDict(self._pmap.get("headers", []))

    def is_multipart(self):
        return self._pmap.get("multi", False)

    def get_subpart(self, part):
        if not self.is_multipart():
            raise TypeError

        sub_pmap = self._pmap.get("part_map", {})

        # XXX BUG --- workaround. Subparts with more than 1 subparts
        # need to get the requested index for the subpart decremented.
        # Off-by-one error, should investigate which is the real reason and
        # fix it, this is only a quick workaround.
        num_parts = self._pmap.get("parts", 0)
        if num_parts > 1:
            part = part - 1
        # -------------------------------------------------------------

        try:
            part_map = sub_pmap[str(part)]
        except KeyError:
            log.msg("getSubpart for %s: KeyError" % (part,))
            raise IndexError

        cdoc_index = _get_index_for_cdoc(part_map, self._cdocs)
        cdoc = self._cdocs.get(cdoc_index, {})

        return MessagePart(part_map, cdocs={1: cdoc}, nested=True)

    def _get_payload(self, index):
        cdoc_wrapper = self._cdocs.get(index, None)
        if cdoc_wrapper:
            return cdoc_wrapper.raw
        return ""


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
        return CaseInsensitiveDict(self._wrapper.hdoc.headers)

    def get_body_file(self, store):
        """
        Get a file descriptor with the body content.
        """
        def write_and_rewind_if_found(cdoc):
            payload = cdoc.raw if cdoc else ""
            # XXX pass ctype from headers if not multipart?
            if payload:
                payload = _encode_payload(payload, ctype=cdoc.content_type)
            return _write_and_rewind(payload)

        d = defer.maybeDeferred(self._wrapper.get_body, store)
        d.addCallback(write_and_rewind_if_found)
        return d

    def get_size(self):
        """
        Size of the whole message, in octets (including headers).
        """
        total = self._wrapper.fdoc.size
        return total

    def is_multipart(self):
        """
        Return True if this message is multipart.
        """
        return self._wrapper.fdoc.multi

    def get_subpart(self, part):
        """
        :param part: The number of the part to retrieve, indexed from 1.
        :type part: int
        :rtype: MessagePart
        """
        if not self.is_multipart():
            raise TypeError
        try:
            subpart_dict = self._wrapper.get_subpart_dict(part)
        except KeyError:
            raise IndexError

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

    _pending_inserts = dict()

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
        self._listeners = set([])

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

    def get_message_by_sequence_number(self, msn, get_cdocs=False):
        """
        Retrieve a message by its Message Sequence Number.
        :rtype: Deferred
        """
        def get_uid_for_msn(all_uid):
            return all_uid[msn - 1]
        d = self.all_uid_iter()
        d.addCallback(get_uid_for_msn)
        d.addCallback(
            lambda uid: self.get_message_by_uid(
                uid, get_cdocs=get_cdocs))
        d.addErrback(lambda f: log.err(f))
        return d

    def get_message_by_uid(self, uid, absolute=True, get_cdocs=False):
        """
        Retrieve a message by its Unique Identifier.

        If this is a Mailbox collection, that is the message UID, unique for a
        given mailbox, or a relative sequence number depending on the absolute
        flag. For now, only absolute identifiers are supported.
        :rtype: Deferred
        """
        # TODO deprecate absolute flag, it doesn't make sense UID and
        # !absolute. use _by_sequence_number instead.
        if not absolute:
            raise NotImplementedError("Does not support relative ids yet")

        get_doc_fun = self.mbox_indexer.get_doc_id_from_uid

        def get_msg_from_mdoc_id(doc_id):
            if doc_id is None:
                return None
            return self.adaptor.get_msg_from_mdoc_id(
                self.messageklass, self.store,
                doc_id, uid=uid, get_cdocs=get_cdocs)

        def cleanup_and_get_doc_after_pending_insert(result):
            for key in result:
                self._pending_inserts.pop(key, None)
            return get_doc_fun(self.mbox_uuid, uid)

        if not self._pending_inserts:
            d = get_doc_fun(self.mbox_uuid, uid)
        else:
            d = defer.gatherResults(self._pending_inserts.values())
            d.addCallback(cleanup_and_get_doc_after_pending_insert)
        d.addCallback(get_msg_from_mdoc_id)
        return d

    def get_flags_by_uid(self, uid, absolute=True):
        # TODO use sequence numbers
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

        :param raw_msg: the raw message
        :param flags: tuple of flags for this message
        :param tags: tuple of tags for this message
        :param date:
            formatted date, it will be used to retrieve the internal
            date for this message.  According to the spec, this is NOT the date
            and time in the RFC-822 header, but rather a date and time that
            reflects when the message was received.
        :type date: str
        :param notify_just_mdoc:
            boolean passed to the wrapper.create method, to indicate whether
            we're insterested in being notified right after the mdoc has been
            written (as it's the first doc to be written, and quite small, this
            is faster, though potentially unsafe), or on the contrary we want
            to wait untill all the parts have been written.
            Used by the imap mailbox implementation to get faster responses.
            This will be ignored (and set to False) if a heuristic for a Draft
            message is met, which currently is a specific mozilla header.
        :type notify_just_mdoc: bool

        :returns: a deferred that will fire with the UID of the inserted
                  message.
        :rtype: deferred
        """
        # TODO watch out if the use of this method in IMAP COPY/APPEND is
        # passing the right date.
        # XXX mdoc ref is a leaky abstraction here. generalize.
        leap_assert_type(flags, tuple)
        leap_assert_type(date, str)

        msg = self.adaptor.get_msg_from_string(Message, raw_msg)
        wrapper = msg.get_wrapper()

        headers = lowerdict(msg.get_headers())
        moz_draft_hdr = "X-Mozilla-Draft-Info"
        if moz_draft_hdr.lower() in headers:
            log.msg("Setting fast notify to False, Draft detected")
            notify_just_mdoc = False

        if notify_just_mdoc:
            msgid = headers.get('message-id')
            if msgid:
                self._pending_inserts[msgid] = defer.Deferred()

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
            if not doc_id:
                # --- BUG -----------------------------------------
                # XXX watch out, sometimes mdoc doesn't have doc_id
                # but it has future_id. Should be solved already.
                logger.error("BUG: (please report) Null doc_id for "
                             "document %s" %
                             (wrapper.mdoc.serialize(),))
                return defer.succeed("mdoc_id not inserted")
                # XXX BUG -----------------------------------------

            # XXX BUG sometimes the table is not yet created,
            # so workaround is to make sure we always check for it before
            # inserting the doc. I should debug into the real cause.
            d = self.mbox_indexer.create_table(self.mbox_uuid)
            d.addBoth(lambda _: self.mbox_indexer.insert_doc(
                self.mbox_uuid, doc_id))
            return d

        d = wrapper.create(
            self.store,
            notify_just_mdoc=notify_just_mdoc,
            pending_inserts_dict=self._pending_inserts)
        d.addCallback(insert_mdoc_id, wrapper)
        d.addCallback(self.cb_signal_unread_to_ui)
        d.addCallback(self.notify_new_to_listeners)
        d.addErrback(lambda failure: log.err(failure))

        return d

    # Listeners

    def addListener(self, listener):
        self._listeners.add(listener)

    def removeListener(self, listener):
        self._listeners.remove(listener)

    def notify_new_to_listeners(self, result):
        for listener in self._listeners:
            listener.notify_new()
        return result

    def cb_signal_unread_to_ui(self, result):
        """
        Sends an unread event to ui, passing *only* the number of unread
        messages if *this* is the inbox. This event is catched, for instance,
        in the Bitmask client that displays a message with the number of unread
        mails in the INBOX.

        Used as a callback in several commands.

        :param result: ignored
        """
        # TODO it might make sense to modify the event so that
        # it receives both the mailbox name AND the number of unread messages.
        if self.mbox_name.lower() == "inbox":
            d = defer.maybeDeferred(self.count_unseen)
            d.addCallback(self.__cb_signal_unread_to_ui)
        return result

    def __cb_signal_unread_to_ui(self, unseen):
        """
        Send the unread signal to UI.
        :param unseen: number of unseen messages.
        :type unseen: int
        """
        emit_async(catalog.MAIL_UNREAD_MESSAGES, self.store.uuid, str(unseen))

    def copy_msg(self, msg, new_mbox_uuid):
        """
        Copy the message to another collection. (it only makes sense for
        mailbox collections)
        """
        # TODO should CHECK first if the mdoc is present in the mailbox
        # WITH a Deleted flag... and just simply remove the flag...
        # Another option is to delete the previous mdoc if it already exists
        # (so we get a new UID)

        if not self.is_mailbox_collection():
            raise NotImplementedError()

        def delete_mdoc_entry_and_insert(failure, mbox_uuid, doc_id):
            d = self.mbox_indexer.delete_doc_by_hash(mbox_uuid, doc_id)
            d.addCallback(lambda _: self.mbox_indexer.insert_doc(
                new_mbox_uuid, doc_id))
            return d

        def insert_copied_mdoc_id(wrapper_new_msg):
            # XXX FIXME -- since this is already saved, the future_doc_id
            # should be already copied into the doc_id!
            # Investigate why we are not receiving the already saved doc_id
            doc_id = wrapper_new_msg.mdoc.doc_id
            if not doc_id:
                doc_id = wrapper_new_msg.mdoc._future_doc_id

            def insert_conditionally(uid, mbox_uuid, doc_id):
                indexer = self.mbox_indexer
                if uid:
                    d = indexer.delete_doc_by_hash(mbox_uuid, doc_id)
                    d.addCallback(lambda _: indexer.insert_doc(
                        new_mbox_uuid, doc_id))
                    return d
                else:
                    d = indexer.insert_doc(mbox_uuid, doc_id)
                    return d

            def log_result(result):
                return result

            def insert_doc(_, mbox_uuid, doc_id):
                d = self.mbox_indexer.get_uid_from_doc_id(mbox_uuid, doc_id)
                d.addCallback(insert_conditionally, mbox_uuid, doc_id)
                d.addErrback(lambda err: log.failure(err))
                d.addCallback(log_result)
                return d

            d = self.mbox_indexer.create_table(new_mbox_uuid)
            d.addBoth(insert_doc, new_mbox_uuid, doc_id)
            return d

        wrapper = msg.get_wrapper()

        d = wrapper.copy(self.store, new_mbox_uuid)
        d.addCallback(insert_copied_mdoc_id)
        d.addCallback(self.notify_new_to_listeners)
        return d

    def delete_msg(self, msg):
        """
        Delete this message.
        """
        wrapper = msg.get_wrapper()

        def delete_mdoc_id(_, wrapper):
            doc_id = wrapper.mdoc.doc_id
            return self.mbox_indexer.delete_doc_by_hash(
                self.mbox_uuid, doc_id)
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

            def return_uids_when_deleted(ignored):
                return uids

            all_deleted = defer.gatherResults(d).addCallback(
                return_uids_when_deleted)
            return all_deleted

        mdocs_deleted = self.adaptor.del_all_flagged_messages(
            self.store, self.mbox_uuid)
        mdocs_deleted.addCallback(get_uid_list)
        mdocs_deleted.addCallback(delete_uid_entries)
        mdocs_deleted.addErrback(lambda f: log.err(f))
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

    # this is a defaultdict, indexed by userid, that returns a
    # WeakValueDictionary mapping to collection instances so that we always
    # return a reference to them instead of creating new ones. however,
    # being a dictionary of weakrefs values, they automagically vanish
    # from the dict when no hard refs is left to them (so they can be
    # garbage collected) this is important because the different wrappers
    # rely on several kinds of deferredlocks that are kept as class or
    # instance variables.

    # We need it to be a class property because we create more than one Account
    # object in the current usage pattern (ie, one in the mail service, and
    # another one in the IncomingMailService). When we move to a proper service
    # tree we can let it be an instance attribute.
    _collection_mapping = defaultdict(weakref.WeakValueDictionary)

    def __init__(self, store, user_id, ready_cb=None):
        self.store = store
        self.user_id = user_id
        self.adaptor = self.adaptor_class()

        self.mbox_indexer = MailboxIndexer(self.store)

        # This flag is only used from the imap service for the moment.
        # In the future, we should prevent any public method to continue if
        # this is set to True. Also, it would be good to plug to the
        # authentication layer.
        self.session_ended = False

        self.deferred_initialization = defer.Deferred()
        self._ready_cb = ready_cb

        self._init_d = self._initialize_storage()
        self._initialize_sync_hooks()

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

    # Sync hooks

    def _initialize_sync_hooks(self):
        soledad_sync_hooks.post_sync_uid_reindexer.set_account(self)

    def _teardown_sync_hooks(self):
        soledad_sync_hooks.post_sync_uid_reindexer.set_account(None)

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

    def add_mailbox(self, name, creation_ts=None):

        if creation_ts is None:
            # by default, we pass an int value
            # taken from the current time
            # we make sure to take enough decimals to get a unique
            # mailbox-uidvalidity.
            creation_ts = int(time.time() * 10E2)

        def set_creation_ts(wrapper):
            wrapper.created = creation_ts
            d = wrapper.update(self.store)
            d.addCallback(lambda _: wrapper)
            return d

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
        d.addCallback(set_creation_ts)
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

        def _rename_mbox(wrapper):
            wrapper.mbox = newname
            d = wrapper.update(self.store)
            d.addCallback(lambda result: wrapper)
            return d

        d = self.adaptor.get_or_create_mbox(self.store, oldname)
        d.addCallback(_rename_mbox)
        return d

    # Get Collections

    def get_collection_by_mailbox(self, name):
        """
        :rtype: deferred
        :return: a deferred that will fire with a MessageCollection
        """
        collection = self._collection_mapping[self.user_id].get(
            name, None)
        if collection:
            return defer.succeed(collection)

        # imap select will use this, passing the collection to SoledadMailbox
        def get_collection_for_mailbox(mbox_wrapper):
            collection = MessageCollection(
                self.adaptor, self.store, self.mbox_indexer, mbox_wrapper)
            self._collection_mapping[self.user_id][name] = collection
            return collection

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

    # Session handling

    def end_session(self):
        self._teardown_sync_hooks()
        self.session_ended = True
