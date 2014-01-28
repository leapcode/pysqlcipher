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
from zope.interface import implements

from leap.common.check import leap_assert_type
from leap.mail.imap.messageparts import MessagePartType
from leap.mail.imap.messageparts import MessageWrapper
from leap.mail.imap.messageparts import RecentFlagsDoc
from leap.mail.imap.fields import fields
from leap.mail.imap.interfaces import IMessageStore
from leap.mail.messageflow import IMessageConsumer
from leap.mail.utils import first

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

        if len(header_docs) != 1:
            logger.warning("Found more than one copy of chash %s!"
                           % (chash,))
        logger.debug("Found header doc with that hash! Skipping save!")
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

        if len(attach_docs) != 1:
            logger.warning("Found more than one copy of phash %s!"
                           % (phash,))
        logger.debug("Found attachment doc with that hash! Skipping save!")
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

    implements(IMessageConsumer, IMessageStore)

    def __init__(self, soledad):
        """
        Initialize the permanent store that writes to Soledad database.

        :param soledad: the soledad instance
        :type soledad: Soledad
        """
        self._soledad = soledad

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

    def consume(self, queue):
        """
        Creates a new document in soledad db.

        :param queue: queue to get item from, with content of the document
                      to be inserted.
        :type queue: Queue
        """
        # TODO should delete the original message from incoming only after
        # the writes are done.
        # TODO should handle the delete case
        # TODO should handle errors
        # TODO could generalize this method into a generic consumer
        # and only implement `process` here

        while not queue.empty():
            items = self._process(queue)

            # we prime the generator, that should return the
            # message or flags wrapper item in the first place.
            doc_wrapper = items.next()

            # From here, we unpack the subpart items and
            # the right soledad call.
            try:
                failed = False
                for item, call in items:
                    try:
                        self._try_call(call, item)
                    except Exception as exc:
                        failed = exc
                        continue
                if failed:
                    raise MsgWriteError

            except MsgWriteError:
                logger.error("Error while processing item.")
                logger.exception(failed)
            else:
                if isinstance(doc_wrapper, MessageWrapper):
                    # If everything went well, we can unset the new flag
                    # in the source store (memory store)
                    logger.info("unsetting new flag!")
                    doc_wrapper.new = False
                    doc_wrapper.dirty = False

    #
    # SoledadStore specific methods.
    #

    def _process(self, queue):
        """
        Return an iterator that will yield the msg_wrapper in the first place,
        followed by the subparts item and the proper call type for every
        item in the queue, if any.

        :param queue: the queue from where we'll pick item.
        :type queue: Queue
        """
        doc_wrapper = queue.get()

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
            call = self._soledad.create_doc

            # item is expected to be a MessagePartDoc
            for item in msg_wrapper.walk():
                if item.part == MessagePartType.fdoc:

                    # FIXME add content duplication for HEADERS too!
                    # (only 1 chash per mailbox!)
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
            call = self._soledad.put_doc
            # item is expected to be a MessagePartDoc
            for item in msg_wrapper.walk():
                # XXX FIXME Give error if dirty and not doc_id !!!
                doc_id = item.doc_id  # defend!
                if not doc_id:
                    continue
                doc = self._soledad.get_doc(doc_id)
                doc.content = dict(item.content)
                if item.part == MessagePartType.fdoc:
                    logger.debug("PUT dirty fdoc")
                    yield doc, call

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
        call = self._soledad.put_doc
        rdoc = self._soledad.get_doc(rflags_wrapper.doc_id)

        payload = rflags_wrapper.content
        logger.debug("Saving RFLAGS to Soledad...")

        if payload:
            rdoc.content = payload
            yield rdoc, call

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
        """
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
                logger.error("%s:%s Tried to write a UID lesser than what's "
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
