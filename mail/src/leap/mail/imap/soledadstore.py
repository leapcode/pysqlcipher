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

from itertools import chain

from u1db import errors as u1db_errors
from zope.interface import implements

from leap.mail.imap.messageparts import MessagePartType
from leap.mail.imap.fields import fields
from leap.mail.imap.interfaces import IMessageStore
from leap.mail.messageflow import IMessageConsumer

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

        :param doc: tentative header document
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
        # XXX re-enable
        #logger.debug("Found header doc with that hash! Skipping save!")
        return True

    def _content_does_exist(self, doc):
        """
        Check whether we already have a content document for a payload
        with this hash in our database.

        :param doc: tentative content document
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
        # XXX re-enable
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
        :param uid: the UID that identifies this message in this mailbox.
        :param message: a IMessageContainer implementor.
        """

    def put_message(self, mbox, uid, message):
        """
        Put the passed existing message into this SoledadStore.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        :param message: a IMessageContainer implementor.
        """

    def remove_message(self, mbox, uid):
        """
        Remove the given message from this SoledadStore.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        """

    def get_message(self, mbox, uid):
        """
        Get a IMessageContainer for the given mbox and uid combination.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        """

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

        empty = queue.empty()
        while not empty:
            items = self._process(queue)
            # we prime the generator, that should return the
            # item in the first place.
            msg_wrapper = items.next()

            # From here, we unpack the subpart items and
            # the right soledad call.
            try:
                failed = False
                for item, call in items:
                    try:
                        self._try_call(call, item)
                    except Exception:
                        failed = True
                        continue
                if failed:
                    raise MsgWriteError

            except MsgWriteError:
                logger.error("Error while processing item.")
                pass
            else:
                # If everything went well, we can unset the new flag
                # in the source store (memory store)
                msg_wrapper.new = False
                msg_wrapper.dirty = False
            empty = queue.empty()

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
        msg_wrapper = queue.get()
        return chain((msg_wrapper,),
                     self._get_calls_for_msg_parts(msg_wrapper))

    def _try_call(self, call, item):
        """
        Try to invoke a given call with item as a parameter.
        """
        if not call:
            return
        try:
            call(item)
        except u1db_errors.RevisionConflict as exc:
            logger.error("Error: %r" % (exc,))
            raise exc

    def _get_calls_for_msg_parts(self, msg_wrapper):
        """
        Generator that return the proper call type for a given item.

        :param msg_wrapper: A MessageWrapper
        :type msg_wrapper: IMessageContainer
        """
        call = None

        if msg_wrapper.new is True:
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

                        # XXX DEBUG -------------------
                        print "about to write content-doc ",
                        #import pprint; pprint.pprint(item.content)

                        yield dict(item.content), call

        # For now, the only thing that will be dirty is
        # the flags doc.

        elif msg_wrapper.dirty is True:
            print "DIRTY DOC! ----------------------"
            call = self._soledad.put_doc

            # item is expected to be a MessagePartDoc
            for item in msg_wrapper.walk():
                doc_id = item.doc_id  # defend!
                doc = self._soledad.get_doc(doc_id)
                doc.content = item.content

                if item.part == MessagePartType.fdoc:
                    print "Will PUT the doc: ", doc
                    yield dict(doc), call

                # XXX also for linkage-doc

        # TODO should write back to the queue
        # with the results of the operation.
        # We can write there:
        # (*) MsgWriteACK  --> Should remove from incoming queue.
        #                      (We should do this here).
        # Implement using callbacks for each operation.

        else:
            logger.error("Cannot put/delete documents yet!")
