# -*- coding: utf-8 -*-
# soledadstore.py
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
A MessageStore that writes to Soledad.
"""
import logging
import threading

from collections import defaultdict
from itertools import chain

from u1db import errors as u1db_errors
from twisted.python import log
from zope.interface import implements

from leap.common.check import leap_assert_type, leap_assert
from leap.mail.decorators import deferred_to_thread
from leap.mail.imap.messageparts import MessagePartType
from leap.mail.imap.messageparts import MessageWrapper
from leap.mail.imap.messageparts import RecentFlagsDoc
from leap.mail.imap.fields import fields
from leap.mail.imap.interfaces import IMessageStore
from leap.mail.messageflow import IMessageConsumer
from leap.mail.utils import first, empty, accumulator_queue

logger = logging.getLogger(__name__)


class ContentDedup(object):
    """
    Message deduplication.

    We do a query for the content hashes before writing to our beloved
    sqlcipher backend of Soledad. This means, by now, that:

    1. We will not store the same body/attachment twice, only the hash of it.
    2. We will not store the same message header twice, only the hash of it.

    The first case is useful if you are always receiving the same old memes
    from unwary friends that still have not discovered that 4chan is the
    generator of the internet. The second will save your day if you have
    initiated session with the same account in two different machines. I also
    wonder why would you do that, but let's respect each other choices, like
    with the religious celebrations, and assume that one day we'll be able
    to run Bitmask in completely free phones. Yes, I mean that, the whole GSM
    Stack.
    """
    # TODO refactor using unique_query

    def _header_does_exist(self, doc):
        """
        Check whether we already have a header document for this
        content hash in our database.

        :param doc: tentative header for document
        :type doc: dict
        :returns: True if it exists, False otherwise.
        """
        if not doc:
            return False
        chash = doc[fields.CONTENT_HASH_KEY]
        header_docs = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_HEADERS_VAL, str(chash))
        if not header_docs:
            return False

        # FIXME enable only to debug this problem.
        #if len(header_docs) != 1:
            #logger.warning("Found more than one copy of chash %s!"
                           #% (chash,))

        #logger.debug("Found header doc with that hash! Skipping save!")
        return True

    def _content_does_exist(self, doc):
        """
        Check whether we already have a content document for a payload
        with this hash in our database.

        :param doc: tentative content for document
        :type doc: dict
        :returns: True if it exists, False otherwise.
        """
        if not doc:
            return False
        phash = doc[fields.PAYLOAD_HASH_KEY]
        attach_docs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_CONTENT_VAL, str(phash))
        if not attach_docs:
            return False

        # FIXME enable only to debug this problem
        #if len(attach_docs) != 1:
            #logger.warning("Found more than one copy of phash %s!"
                           #% (phash,))
        #logger.debug("Found attachment doc with that hash! Skipping save!")
        return True


class MsgWriteError(Exception):
    """
    Raised if any exception is found while saving message parts.
    """
    pass


"""
A lock per document.
"""
# TODO should bound the space of this!!!
# http://stackoverflow.com/a/2437645/1157664
# Setting this to twice the number of threads in the threadpool
# should be safe.

put_locks = defaultdict(lambda: threading.Lock())
mbox_doc_locks = defaultdict(lambda: threading.Lock())


class SoledadStore(ContentDedup):
    """
    This will create docs in the local Soledad database.
    """
    _remove_lock = threading.Lock()

    implements(IMessageConsumer, IMessageStore)

    def __init__(self, soledad):
        """
        Initialize the permanent store that writes to Soledad database.

        :param soledad: the soledad instance
        :type soledad: Soledad
        """
        from twisted.internet import reactor
        self.reactor = reactor

        self._soledad = soledad

        self._CREATE_DOC_FUN = self._soledad.create_doc
        self._PUT_DOC_FUN = self._soledad.put_doc
        self._GET_DOC_FUN = self._soledad.get_doc

        # we instantiate an accumulator to batch the notifications
        self.docs_notify_queue = accumulator_queue(
            lambda item: reactor.callFromThread(self._unset_new_dirty, item),
            20)

    # IMessageStore

    # -------------------------------------------------------------------
    # We are not yet using this interface, but it would make sense
    # to implement it.

    def create_message(self, mbox, uid, message):
        """
        Create the passed message into this SoledadStore.

        :param mbox: the mbox this message belongs.
        :type mbox: str or unicode
        :param uid: the UID that identifies this message in this mailbox.
        :type uid: int
        :param message: a IMessageContainer implementor.
        """
        raise NotImplementedError()

    def put_message(self, mbox, uid, message):
        """
        Put the passed existing message into this SoledadStore.

        :param mbox: the mbox this message belongs.
        :type mbox: str or unicode
        :param uid: the UID that identifies this message in this mailbox.
        :type uid: int
        :param message: a IMessageContainer implementor.
        """
        raise NotImplementedError()

    def remove_message(self, mbox, uid):
        """
        Remove the given message from this SoledadStore.

        :param mbox: the mbox this message belongs.
        :type mbox: str or unicode
        :param uid: the UID that identifies this message in this mailbox.
        :type uid: int
        """
        raise NotImplementedError()

    def get_message(self, mbox, uid):
        """
        Get a IMessageContainer for the given mbox and uid combination.

        :param mbox: the mbox this message belongs.
        :type mbox: str or unicode
        :param uid: the UID that identifies this message in this mailbox.
        :type uid: int
        """
        raise NotImplementedError()

    # IMessageConsumer

    # TODO should handle the delete case
    # TODO should handle errors better
    # TODO could generalize this method into a generic consumer
    # and only implement `process` here

    def consume(self, queue):
        """
        Creates a new document in soledad db.

        :param queue: a tuple of queues to get item from, with content of the
                      document to be inserted.
        :type queue: tuple of Queues
        """
        new, dirty = queue
        while not new.empty():
            doc_wrapper = new.get()
            self.reactor.callInThread(self._consume_doc, doc_wrapper,
                                      self.docs_notify_queue)
        while not dirty.empty():
            doc_wrapper = dirty.get()
            self.reactor.callInThread(self._consume_doc, doc_wrapper,
                                      self.docs_notify_queue)

        # Queue empty, flush the notifications queue.
        self.docs_notify_queue(None, flush=True)

    def _unset_new_dirty(self, doc_wrapper):
        """
        Unset the `new` and `dirty` flags for this document wrapper in the
        memory store.

        :param doc_wrapper: a MessageWrapper instance
        :type doc_wrapper: MessageWrapper
        """
        if isinstance(doc_wrapper, MessageWrapper):
            # XXX still needed for debug quite often
            #logger.info("unsetting new flag!")
            doc_wrapper.new = False
            doc_wrapper.dirty = False

    @deferred_to_thread
    def _consume_doc(self, doc_wrapper, notify_queue):
        """
        Consume each document wrapper in a separate thread.
        We pass an instance of an accumulator that handles the notifications
        to the memorystore when the write has been done.

        :param doc_wrapper: a MessageWrapper or RecentFlagsDoc instance
        :type doc_wrapper: MessageWrapper or RecentFlagsDoc
        :param notify_queue: a callable that handles the writeback
                             notifications to the memstore.
        :type notify_queue: callable
        """
        def queueNotifyBack(failed, doc_wrapper):
            if failed:
                log.msg("There was an error writing the mesage...")
            else:
                notify_queue(doc_wrapper)

        def doSoledadCalls(items):
            # we prime the generator, that should return the
            # message or flags wrapper item in the first place.
            try:
                doc_wrapper = items.next()
            except StopIteration:
                pass
            else:
                failed = self._soledad_write_document_parts(items)
                queueNotifyBack(failed, doc_wrapper)

        doSoledadCalls(self._iter_wrapper_subparts(doc_wrapper))

    #
    # SoledadStore specific methods.
    #

    def _soledad_write_document_parts(self, items):
        """
        Write the document parts to soledad in a separate thread.

        :param items: the iterator through the different document wrappers
                      payloads.
        :type items: iterator
        :return: whether the write was successful or not
        :rtype: bool
        """
        failed = False
        for item, call in items:
            if empty(item):
                continue
            try:
                self._try_call(call, item)
            except Exception as exc:
                logger.debug("ITEM WAS: %s" % repr(item))
                if hasattr(item, 'content'):
                    logger.debug("ITEM CONTENT WAS: %s" %
                                 repr(item.content))
                logger.exception(exc)
                failed = True
                continue
        return failed

    def _iter_wrapper_subparts(self, doc_wrapper):
        """
        Return an iterator that will yield the doc_wrapper in the first place,
        followed by the subparts item and the proper call type for every
        item in the queue, if any.

        :param doc_wrapper: a MessageWrapper or RecentFlagsDoc instance
        :type doc_wrapper: MessageWrapper or RecentFlagsDoc
        """
        if isinstance(doc_wrapper, MessageWrapper):
            return chain((doc_wrapper,),
                         self._get_calls_for_msg_parts(doc_wrapper))
        elif isinstance(doc_wrapper, RecentFlagsDoc):
            return chain((doc_wrapper,),
                         self._get_calls_for_rflags_doc(doc_wrapper))
        else:
            logger.warning("CANNOT PROCESS ITEM!")
            return (i for i in [])

    def _try_call(self, call, item):
        """
        Try to invoke a given call with item as a parameter.

        :param call: the function to call
        :type call: callable
        :param item: the payload to pass to the call as argument
        :type item: object
        """
        if call is None:
            return

        if call == self._PUT_DOC_FUN:
            doc_id = item.doc_id
            if doc_id is None:
                logger.warning("BUG! Dirty doc but has no doc_id!")
                return
            with put_locks[doc_id]:
                doc = self._GET_DOC_FUN(doc_id)

                if doc is None:
                    logger.warning("BUG! Dirty doc but could not "
                                   "find document %s" % (doc_id,))
                    return

                doc.content = dict(item.content)

                item = doc
                try:
                    call(item)
                except u1db_errors.RevisionConflict as exc:
                    logger.exception("Error: %r" % (exc,))
                    raise exc
                except Exception as exc:
                    logger.exception("Error: %r" % (exc,))
                    raise exc

        else:
            try:
                call(item)
            except u1db_errors.RevisionConflict as exc:
                logger.exception("Error: %r" % (exc,))
                raise exc
            except Exception as exc:
                logger.exception("Error: %r" % (exc,))
                raise exc

    def _get_calls_for_msg_parts(self, msg_wrapper):
        """
        Generator that return the proper call type for a given item.

        :param msg_wrapper: A MessageWrapper
        :type msg_wrapper: IMessageContainer
        :return: a generator of tuples with recent-flags doc payload
                 and callable
        :rtype: generator
        """
        call = None

        if msg_wrapper.new:
            call = self._CREATE_DOC_FUN

            # item is expected to be a MessagePartDoc
            for item in msg_wrapper.walk():
                if item.part == MessagePartType.fdoc:
                    yield dict(item.content), call

                elif item.part == MessagePartType.hdoc:
                    if not self._header_does_exist(item.content):
                        yield dict(item.content), call

                elif item.part == MessagePartType.cdoc:
                    if not self._content_does_exist(item.content):
                        yield dict(item.content), call

        # For now, the only thing that will be dirty is
        # the flags doc.

        elif msg_wrapper.dirty:
            call = self._PUT_DOC_FUN
            # item is expected to be a MessagePartDoc
            for item in msg_wrapper.walk():
                # XXX FIXME Give error if dirty and not doc_id !!!
                doc_id = item.doc_id  # defend!
                if not doc_id:
                    logger.warning("Dirty item but no doc_id!")
                    continue

                if item.part == MessagePartType.fdoc:
                    yield item, call

                # XXX also for linkage-doc !!!
        else:
            logger.error("Cannot delete documents yet from the queue...!")

    def _get_calls_for_rflags_doc(self, rflags_wrapper):
        """
        We always put these documents.

        :param rflags_wrapper: A wrapper around recent flags doc.
        :type rflags_wrapper: RecentFlagsWrapper
        :return: a tuple with recent-flags doc payload and callable
        :rtype: tuple
        """
        call = self._PUT_DOC_FUN

        payload = rflags_wrapper.content
        if payload:
            logger.debug("Saving RFLAGS to Soledad...")
            yield rflags_wrapper, call

    # Mbox documents and attributes

    def get_mbox_document(self, mbox):
        """
        Return mailbox document.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: A SoledadDocument containing this mailbox, or None if
                 the query failed.
        :rtype: SoledadDocument or None.
        """
        with mbox_doc_locks[mbox]:
            return self._get_mbox_document(mbox)

    def _get_mbox_document(self, mbox):
        """
        Helper for returning the mailbox document.
        """
        try:
            query = self._soledad.get_from_index(
                fields.TYPE_MBOX_IDX,
                fields.TYPE_MBOX_VAL, mbox)
            if query:
                return query.pop()
            else:
                logger.error("Could not find mbox document for %r" %
                             (mbox,))
        except Exception as exc:
            logger.exception("Unhandled error %r" % exc)

    def get_mbox_closed(self, mbox):
        """
        Return the closed attribute for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: bool
        """
        mbox_doc = self.get_mbox_document()
        return mbox_doc.content.get(fields.CLOSED_KEY, False)

    def set_mbox_closed(self, mbox, closed):
        """
        Set the closed attribute for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param closed:  the value to be set
        :type closed: bool
        """
        leap_assert(isinstance(closed, bool), "closed needs to be boolean")
        with mbox_doc_locks[mbox]:
            mbox_doc = self._get_mbox_document(mbox)
            if mbox_doc is None:
                logger.error(
                    "Could not find mbox document for %r" % (mbox,))
                return
            mbox_doc.content[fields.CLOSED_KEY] = closed
            self._soledad.put_doc(mbox_doc)

    def write_last_uid(self, mbox, value):
        """
        Write the `last_uid` integer to the proper mailbox document
        in Soledad.
        This is called from the deferred triggered by
        memorystore.increment_last_soledad_uid, which is expected to
        run in a separate thread.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param value: the value to set
        :type value: int
        """
        leap_assert_type(value, int)
        key = fields.LAST_UID_KEY

        # XXX use accumulator to reduce number of hits
        with mbox_doc_locks[mbox]:
            mbox_doc = self._get_mbox_document(mbox)
            old_val = mbox_doc.content[key]
            if value > old_val:
                mbox_doc.content[key] = value
                try:
                    self._soledad.put_doc(mbox_doc)
                except Exception as exc:
                    logger.error("Error while setting last_uid for %r"
                                 % (mbox,))
                    logger.exception(exc)

    def get_flags_doc(self, mbox, uid):
        """
        Return the SoledadDocument for the given mbox and uid.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the UID for the message
        :type uid: int
        :rtype: SoledadDocument or None
        """
        # TODO -- inlineCallbacks
        result = None
        try:
            # TODO -- yield
            flag_docs = self._soledad.get_from_index(
                fields.TYPE_MBOX_UID_IDX,
                fields.TYPE_FLAGS_VAL, mbox, str(uid))
            if len(flag_docs) != 1:
                logger.warning("More than one flag doc for %r:%s" %
                               (mbox, uid))
            result = first(flag_docs)
        except Exception as exc:
            # ugh! Something's broken down there!
            logger.warning("ERROR while getting flags for UID: %s" % uid)
            logger.exception(exc)
        finally:
            return result

    def get_headers_doc(self, chash):
        """
        Return the document that keeps the headers for a message
        indexed by its content-hash.

        :param chash: the content-hash to retrieve the document from.
        :type chash: str or unicode
        :rtype: SoledadDocument or None
        """
        head_docs = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_HEADERS_VAL, str(chash))
        return first(head_docs)

    # deleted messages

    def deleted_iter(self, mbox):
        """
        Get an iterator for the the doc_id for SoledadDocuments for messages
        with \\Deleted flag for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: iterator through deleted message docs
        :rtype: iterable
        """
        return [doc.doc_id for doc in self._soledad.get_from_index(
                fields.TYPE_MBOX_DEL_IDX,
                fields.TYPE_FLAGS_VAL, mbox, '1')]

    def remove_all_deleted(self, mbox):
        """
        Remove from Soledad all messages flagged as deleted for a given
        mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        deleted = []
        for doc_id in self.deleted_iter(mbox):
            with self._remove_lock:
                doc = self._soledad.get_doc(doc_id)
                if doc is not None:
                    self._soledad.delete_doc(doc)
                    try:
                        deleted.append(doc.content[fields.UID_KEY])
                    except TypeError:
                        # empty content
                        pass
        return deleted
