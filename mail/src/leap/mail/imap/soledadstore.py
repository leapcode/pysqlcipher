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

from itertools import chain

from u1db import errors as u1db_errors
from twisted.internet import defer
from twisted.python import log
from zope.interface import implements

from leap.common.check import leap_assert_type
from leap.mail.decorators import deferred_to_thread
from leap.mail.imap.messageparts import MessagePartType
from leap.mail.imap.messageparts import MessageWrapper
from leap.mail.imap.messageparts import RecentFlagsDoc
from leap.mail.imap.fields import fields
from leap.mail.imap.interfaces import IMessageStore
from leap.mail.messageflow import IMessageConsumer
from leap.mail.utils import first, empty

logger = logging.getLogger(__name__)


# TODO
# [ ] Delete original message from the incoming queue after all successful
#     writes.
# [ ] Implement a retry queue.
# [ ] Consider journaling of operations.


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


class SoledadStore(ContentDedup):
    """
    This will create docs in the local Soledad database.
    """
    _last_uid_lock = threading.Lock()
    _soledad_rw_lock = threading.Lock()

    implements(IMessageConsumer, IMessageStore)

    def __init__(self, soledad):
        """
        Initialize the permanent store that writes to Soledad database.

        :param soledad: the soledad instance
        :type soledad: Soledad
        """
        self._soledad = soledad

        self._CREATE_DOC_FUN = self._soledad.create_doc
        self._PUT_DOC_FUN = self._soledad.put_doc
        self._GET_DOC_FUN = self._soledad.get_doc

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

    # It's not thread-safe to defer this to a different thread

    def consume(self, queue):
        """
        Creates a new document in soledad db.

        :param queue: queue to get item from, with content of the document
                      to be inserted.
        :type queue: Queue
        """
        # TODO should handle the delete case
        # TODO should handle errors better
        # TODO could generalize this method into a generic consumer
        # and only implement `process` here

        from twisted.internet import reactor

        def docWriteCallBack(doc_wrapper):
            """
            Callback for a successful write of a document wrapper.
            """
            if isinstance(doc_wrapper, MessageWrapper):
                # If everything went well, we can unset the new flag
                # in the source store (memory store)
                self._unset_new_dirty(doc_wrapper)

        def docWriteErrorBack(failure):
            """
            Errorback for write operations.
            """
            log.msg("ERROR: Error while processing item.")
            log.msg(failure.getTraceback())

        while not queue.empty():
            doc_wrapper = queue.get()

            d = defer.Deferred()
            d.addCallbacks(docWriteCallBack, docWriteErrorBack)
            reactor.callLater(0, self._consume_doc, doc_wrapper, d)

    # FIXME this should not run the callback in the deferred thred
    @deferred_to_thread
    def _unset_new_dirty(self, doc_wrapper):
        """
        Unset the `new` and `dirty` flags for this document wrapper in the
        memory store.

        :param doc_wrapper: a MessageWrapper instance
        :type doc_wrapper: MessageWrapper
        """
        # XXX debug msg id/mbox?
        logger.info("unsetting new flag!")
        doc_wrapper.new = False
        doc_wrapper.dirty = False

    def _consume_doc(self, doc_wrapper, deferred):
        """
        Consume each document wrapper in a separate thread.

        :param doc_wrapper: a MessageWrapper or RecentFlagsDoc instance
        :type doc_wrapper: MessageWrapper or RecentFlagsDoc
        :param deferred: a deferred that will be fired when the write operation
                         has finished, either calling its callback or its
                         errback depending on whether it succeed.
        :type deferred: Deferred
        """
        def notifyBack(failed, observer, doc_wrapper):
            if failed:
                observer.errback(MsgWriteError(
                    "There was an error writing the mesage"))
            else:
                observer.callback(doc_wrapper)

        def doSoledadCalls(items, observer):
            # we prime the generator, that should return the
            # message or flags wrapper item in the first place.
            doc_wrapper = items.next()
            d_sol = self._soledad_write_document_parts(items)
            d_sol.addCallback(notifyBack, observer, doc_wrapper)
            d_sol.addErrback(ebSoledadCalls)

        def ebSoledadCalls(failure):
            log.msg(failure.getTraceback())

        d = self._iter_wrapper_subparts(doc_wrapper)
        d.addCallback(doSoledadCalls, deferred)
        d.addErrback(ebSoledadCalls)

    #
    # SoledadStore specific methods.
    #

    @deferred_to_thread
    def _soledad_write_document_parts(self, items):
        """
        Write the document parts to soledad in a separate thread.
        :param items: the iterator through the different document wrappers
                      payloads.
        :type items: iterator
        """
        failed = False
        for item, call in items:
            if empty(item):
                continue
            try:
                self._try_call(call, item)
            except Exception as exc:
                logger.exception(exc)
                failed = True
                continue
        return failed

    @deferred_to_thread
    def _iter_wrapper_subparts(self, doc_wrapper):
        """
        Return an iterator that will yield the doc_wrapper in the first place,
        followed by the subparts item and the proper call type for every
        item in the queue, if any.

        :param queue: the queue from where we'll pick item.
        :type queue: Queue
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

        with self._soledad_rw_lock:
            if call == self._PUT_DOC_FUN:
                doc_id = item.doc_id
                doc = self._GET_DOC_FUN(doc_id)
                doc.content = dict(item.content)
                item = doc

            try:
                call(item)
            except u1db_errors.RevisionConflict as exc:
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
                    continue

                if item.part == MessagePartType.fdoc:
                    logger.debug("PUT dirty fdoc")
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
        call = self._CREATE_DOC_FUN

        payload = rflags_wrapper.content
        if payload:
            logger.debug("Saving RFLAGS to Soledad...")
            yield payload, call

    def _get_mbox_document(self, mbox):
        """
        Return mailbox document.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: A SoledadDocument containing this mailbox, or None if
                 the query failed.
        :rtype: SoledadDocument or None.
        """
        try:
            query = self._soledad.get_from_index(
                fields.TYPE_MBOX_IDX,
                fields.TYPE_MBOX_VAL, mbox)
            if query:
                return query.pop()
        except Exception as exc:
            logger.exception("Unhandled error %r" % exc)

    def get_flags_doc(self, mbox, uid):
        """
        Return the SoledadDocument for the given mbox and uid.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the UID for the message
        :type uid: int
        :rtype: SoledadDocument or None
        """
        result = None
        try:
            flag_docs = self._soledad.get_from_index(
                fields.TYPE_MBOX_UID_IDX,
                fields.TYPE_FLAGS_VAL, mbox, str(uid))
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

        with self._last_uid_lock:
            mbox_doc = self._get_mbox_document(mbox)
            old_val = mbox_doc.content[key]
            if value < old_val:
                logger.error("%r:%s Tried to write a UID lesser than what's "
                             "stored!" % (mbox, value))
            mbox_doc.content[key] = value
            self._soledad.put_doc(mbox_doc)

    # deleted messages

    def deleted_iter(self, mbox):
        """
        Get an iterator for the SoledadDocuments for messages
        with \\Deleted flag for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: iterator through deleted message docs
        :rtype: iterable
        """
        return (doc for doc in self._soledad.get_from_index(
                fields.TYPE_MBOX_DEL_IDX,
                fields.TYPE_FLAGS_VAL, mbox, '1'))

    # TODO can deferToThread this?
    def remove_all_deleted(self, mbox):
        """
        Remove from Soledad all messages flagged as deleted for a given
        mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        deleted = []
        for doc in self.deleted_iter(mbox):
            deleted.append(doc.content[fields.UID_KEY])
            self._soledad.delete_doc(doc)
        return deleted
