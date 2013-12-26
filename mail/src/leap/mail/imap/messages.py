# -*- coding: utf-8 -*-
# messages.py
# Copyright (C) 2013 LEAP
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
LeapMessage and MessageCollection.
"""
import copy
import logging
import StringIO
from collections import namedtuple

from twisted.mail import imap4
from twisted.python import log
from u1db import errors as u1db_errors
from zope.interface import implements
from zope.proxy import sameProxiedObjects

from leap.common.check import leap_assert, leap_assert_type
from leap.common.mail import get_email_charset
from leap.mail.decorators import deferred
from leap.mail.imap.account import SoledadBackedAccount
from leap.mail.imap.index import IndexedDB
from leap.mail.imap.fields import fields, WithMsgFields
from leap.mail.imap.parser import MailParser, MBoxParser
from leap.mail.messageflow import IMessageConsumer, MessageProducer

logger = logging.getLogger(__name__)


class LeapMessage(fields, MailParser, MBoxParser):

    implements(imap4.IMessage)

    def __init__(self, soledad, uid, mbox):
        """
        Initializes a LeapMessage.

        :param soledad: a Soledad instance
        :type soledad: Soledad
        :param uid: the UID for the message.
        :type uid: int or basestring
        :param mbox: the mbox this message belongs to
        :type mbox: basestring
        """
        MailParser.__init__(self)
        self._soledad = soledad
        self._uid = int(uid)
        self._mbox = self._parse_mailbox_name(mbox)
        self._chash = None

        self.__cdoc = None

    @property
    def _fdoc(self):
        """
        An accessor to the flags document.
        """
        return self._get_flags_doc()

    @property
    def _cdoc(self):
        """
        An accessor to the content document.
        """
        if not self.__cdoc:
            self.__cdoc = self._get_content_doc()
        return self.__cdoc

    @property
    def _chash(self):
        """
        An accessor to the content hash for this message.
        """
        if not self._fdoc:
            return None
        return self._fdoc.content.get(fields.CONTENT_HASH_KEY, None)

    # IMessage implementation

    def getUID(self):
        """
        Retrieve the unique identifier associated with this message

        :return: uid for this message
        :rtype: int
        """
        return self._uid

    def getFlags(self):
        """
        Retrieve the flags associated with this message

        :return: The flags, represented as strings
        :rtype: tuple
        """
        if self._uid is None:
            return []

        flags = []
        flag_doc = self._fdoc
        if flag_doc:
            flags = flag_doc.content.get(self.FLAGS_KEY, None)
        if flags:
            flags = map(str, flags)
        return tuple(flags)

    # setFlags, addFlags, removeFlags are not in the interface spec
    # but we use them with store command.

    def setFlags(self, flags):
        """
        Sets the flags for this message

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to update in the message.
        :type flags: tuple of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        log.msg('setting flags: %s' % (self._uid))

        doc = self._fdoc
        doc.content[self.FLAGS_KEY] = flags
        doc.content[self.SEEN_KEY] = self.SEEN_FLAG in flags
        doc.content[self.RECENT_KEY] = self.RECENT_FLAG in flags
        self._soledad.put_doc(doc)

    def addFlags(self, flags):
        """
        Adds flags to this message.

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to add to the message.
        :type flags: tuple of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        oldflags = self.getFlags()
        self.setFlags(tuple(set(flags + oldflags)))

    def removeFlags(self, flags):
        """
        Remove flags from this message.

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to be removed from the message.
        :type flags: tuple of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        oldflags = self.getFlags()
        self.setFlags(tuple(set(oldflags) - set(flags)))

    def getInternalDate(self):
        """
        Retrieve the date internally associated with this message

        :rtype: C{str}
        :return: An RFC822-formatted date string.
        """
        return str(self._cdoc.content.get(self.DATE_KEY, ''))

    #
    # IMessagePart
    #

    # XXX we should implement this interface too for the subparts
    # so we allow nested parts...

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        fd = StringIO.StringIO()

        cdoc = self._cdoc
        content = cdoc.content.get(self.RAW_KEY, '')
        charset = get_email_charset(
            unicode(cdoc.content.get(self.RAW_KEY, '')))
        try:
            content = content.encode(charset)
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            logger.error("Unicode error {0}".format(e))
            content = content.encode(charset, 'replace')

        raw = self._get_raw_msg()
        msg = self._get_parsed_msg(raw)
        body = msg.get_payload()
        fd.write(body)
        # XXX SHOULD use a separate BODY FIELD ...
        fd.seek(0)
        return fd

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        size = self._cdoc.content.get(self.SIZE_KEY, False)
        if not size:
            # XXX fallback, should remove when all migrated.
            size = self.getBodyFile().len
        return size

    def _get_headers(self):
        """
        Return the headers dict stored in this message document.
        """
        # XXX get from the headers doc
        return self._cdoc.content.get(self.HEADERS_KEY, {})

    def getHeaders(self, negate, *names):
        """
        Retrieve a group of message headers.

        :param names: The names of the headers to retrieve or omit.
        :type names: tuple of str

        :param negate: If True, indicates that the headers listed in names
                       should be omitted from the return value, rather
                       than included.
        :type negate: bool

        :return: A mapping of header field names to header field values
        :rtype: dict
        """
        headers = self._get_headers()
        names = map(lambda s: s.upper(), names)
        if negate:
            cond = lambda key: key.upper() not in names
        else:
            cond = lambda key: key.upper() in names

        # unpack and filter original dict by negate-condition
        filter_by_cond = [
            map(str, (key, val)) for
            key, val in headers.items()
            if cond(key)]
        return dict(filter_by_cond)

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        if self._cdoc:
            retval = self._fdoc.content.get(self.MULTIPART_KEY, False)
            return retval

    def getSubPart(self, part):
        """
        Retrieve a MIME submessage

        :type part: C{int}
        :param part: The number of the part to retrieve, indexed from 0.
        :raise IndexError: Raised if the specified part does not exist.
        :raise TypeError: Raised if this message is not multipart.
        :rtype: Any object implementing C{IMessagePart}.
        :return: The specified sub-part.
        """
        if not self.isMultipart():
            raise TypeError

        msg = self._get_parsed_msg()
        # XXX should wrap IMessagePart
        return msg.get_payload()[part]

    #
    # accessors
    #

    def _get_flags_doc(self):
        """
        Return the document that keeps the flags for this
        message.
        """
        flag_docs = self._soledad.get_from_index(
            SoledadBackedAccount.TYPE_MBOX_UID_IDX,
            fields.TYPE_FLAGS_VAL, self._mbox, str(self._uid))
        flag_doc = flag_docs[0] if flag_docs else None
        return flag_doc

    def _get_content_doc(self):
        """
        Return the document that keeps the flags for this
        message.
        """
        cont_docs = self._soledad.get_from_index(
            SoledadBackedAccount.TYPE_HASH_IDX,
            fields.TYPE_MESSAGE_VAL, self._content_hash, str(self._uid))
        cont_doc = cont_docs[0] if cont_docs else None
        return cont_doc

    def _get_raw_msg(self):
        """
        Return the raw msg.
        :rtype: basestring
        """
        return self._cdoc.content.get(self.RAW_KEY, '')

    def __getitem__(self, key):
        """
        Return the content of the message document.

        :param key: The key
        :type key: str

        :return: The content value indexed by C{key} or None
        :rtype: str
        """
        return self._cdoc.content.get(key, None)

    def does_exist(self):
        """
        Return True if there is actually a message for this
        UID and mbox.
        """
        return bool(self._fdoc)


SoledadWriterPayload = namedtuple(
    'SoledadWriterPayload', ['mode', 'payload'])

SoledadWriterPayload.CREATE = 1
SoledadWriterPayload.PUT = 2


class SoledadDocWriter(object):
    """
    This writer will create docs serially in the local soledad database.
    """

    implements(IMessageConsumer)

    def __init__(self, soledad):
        """
        Initialize the writer.

        :param soledad: the soledad instance
        :type soledad: Soledad
        """
        self._soledad = soledad

    def consume(self, queue):
        """
        Creates a new document in soledad db.

        :param queue: queue to get item from, with content of the document
                      to be inserted.
        :type queue: Queue
        """
        empty = queue.empty()
        while not empty:
            item = queue.get()
            if item.mode == SoledadWriterPayload.CREATE:
                call = self._soledad.create_doc
            elif item.mode == SoledadWriterPayload.PUT:
                call = self._soledad.put_doc

            # should handle errors
            try:
                call(item.payload)
            except u1db_errors.RevisionConflict as exc:
                logger.error("Error: %r" % (exc,))
                raise exc

            empty = queue.empty()


class MessageCollection(WithMsgFields, IndexedDB, MailParser, MBoxParser):
    """
    A collection of messages, surprisingly.

    It is tied to a selected mailbox name that is passed to constructor.
    Implements a filter query over the messages contained in a soledad
    database.
    """
    # XXX this should be able to produce a MessageSet methinks

    EMPTY_MSG = {
        fields.TYPE_KEY: fields.TYPE_MESSAGE_VAL,
        fields.UID_KEY: 1,
        fields.MBOX_KEY: fields.INBOX_VAL,

        fields.SUBJECT_KEY: "",
        fields.DATE_KEY: "",
        fields.RAW_KEY: "",

        # XXX should separate headers into another doc
        fields.HEADERS_KEY: {},
    }

    EMPTY_FLAGS = {
        fields.TYPE_KEY: fields.TYPE_FLAGS_VAL,
        fields.UID_KEY: 1,
        fields.MBOX_KEY: fields.INBOX_VAL,

        fields.FLAGS_KEY: [],
        fields.SEEN_KEY: False,
        fields.RECENT_KEY: True,
        fields.MULTIPART_KEY: False,
    }

    # get from SoledadBackedAccount the needed index-related constants
    INDEXES = SoledadBackedAccount.INDEXES
    TYPE_IDX = SoledadBackedAccount.TYPE_IDX

    def __init__(self, mbox=None, soledad=None):
        """
        Constructor for MessageCollection.

        :param mbox: the name of the mailbox. It is the name
                     with which we filter the query over the
                     messages database
        :type mbox: str

        :param soledad: Soledad database
        :type soledad: Soledad instance
        """
        MailParser.__init__(self)
        leap_assert(mbox, "Need a mailbox name to initialize")
        leap_assert(mbox.strip() != "", "mbox cannot be blank space")
        leap_assert(isinstance(mbox, (str, unicode)),
                    "mbox needs to be a string")
        leap_assert(soledad, "Need a soledad instance to initialize")

        # okay, all in order, keep going...
        self.mbox = self._parse_mailbox_name(mbox)
        self._soledad = soledad
        self.initialize_db()

        # I think of someone like nietzsche when reading this

        # this will be the producer that will enqueue the content
        # to be processed serially by the consumer (the writer). We just
        # need to `put` the new material on its plate.

        self.soledad_writer = MessageProducer(
            SoledadDocWriter(soledad),
            period=0.05)

    def _get_empty_msg(self):
        """
        Returns an empty message.

        :return: a dict containing a default empty message
        :rtype: dict
        """
        return copy.deepcopy(self.EMPTY_MSG)

    def _get_empty_flags_doc(self):
        """
        Returns an empty doc for storing flags.

        :return:
        :rtype:
        """
        return copy.deepcopy(self.EMPTY_FLAGS)

    @deferred
    def add_msg(self, raw, subject=None, flags=None, date=None, uid=1):
        """
        Creates a new message document.

        :param raw: the raw message
        :type raw: str

        :param subject: subject of the message.
        :type subject: str

        :param flags: flags
        :type flags: list

        :param date: the received date for the message
        :type date: str

        :param uid: the message uid for this mailbox
        :type uid: int
        """
        # TODO: split in smaller methods
        logger.debug('adding message')
        if flags is None:
            flags = tuple()
        leap_assert_type(flags, tuple)

        content_doc = self._get_empty_msg()
        flags_doc = self._get_empty_flags_doc()

        content_doc[self.MBOX_KEY] = self.mbox
        flags_doc[self.MBOX_KEY] = self.mbox
        # ...should get a sanity check here.
        content_doc[self.UID_KEY] = uid
        flags_doc[self.UID_KEY] = uid

        if flags:
            flags_doc[self.FLAGS_KEY] = map(self._stringify, flags)
            flags_doc[self.SEEN_KEY] = self.SEEN_FLAG in flags

        msg = self._get_parsed_msg(raw)
        headers = dict(msg)

        logger.debug("adding. is multipart:%s" % msg.is_multipart())
        flags_doc[self.MULTIPART_KEY] = msg.is_multipart()
        # XXX get lower case for keys?
        # XXX get headers doc
        content_doc[self.HEADERS_KEY] = headers
        # set subject based on message headers and eventually replace by
        # subject given as param
        if self.SUBJECT_FIELD in headers:
            content_doc[self.SUBJECT_KEY] = headers[self.SUBJECT_FIELD]
        if subject is not None:
            content_doc[self.SUBJECT_KEY] = subject

        # XXX could separate body into its own doc
        # but should also separate multiparts
        # that should be wrapped in MessagePart
        content_doc[self.RAW_KEY] = self._stringify(raw)
        content_doc[self.SIZE_KEY] = len(raw)

        if not date and self.DATE_FIELD in headers:
            content_doc[self.DATE_KEY] = headers[self.DATE_FIELD]
        else:
            content_doc[self.DATE_KEY] = date

        logger.debug('enqueuing message for write')

        ptuple = SoledadWriterPayload
        self.soledad_writer.put(ptuple(
            mode=ptuple.CREATE, payload=content_doc))
        self.soledad_writer.put(ptuple(
            mode=ptuple.CREATE, payload=flags_doc))

    def remove(self, msg):
        """
        Removes a message.

        :param msg: a  Leapmessage instance
        :type msg: LeapMessage
        """
        # XXX remove
        #self._soledad.delete_doc(msg)
        msg.remove()

    # getters

    def get_msg_by_uid(self, uid):
        """
        Retrieves a LeapMessage by UID.

        :param uid: the message uid to query by
        :type uid: int

        :return: A LeapMessage instance matching the query,
                 or None if not found.
        :rtype: LeapMessage
        """
        msg = LeapMessage(self._soledad, uid, self.mbox)
        if not msg.does_exist():
            return None
        return msg

    def get_all_docs(self, _type=fields.TYPE_FLAGS_VAL):
        """
        Get all documents for the selected mailbox of the
        passed type. By default, it returns the flag docs.

        If you want acess to the content, use __iter__ instead

        :return: a list of u1db documents
        :rtype: list of SoledadDocument
        """
        if _type not in fields.__dict__.values():
            raise TypeError("Wrong type passed to get_all")

        if sameProxiedObjects(self._soledad, None):
            logger.warning('Tried to get messages but soledad is None!')
            return []

        all_docs = [doc for doc in self._soledad.get_from_index(
            SoledadBackedAccount.TYPE_MBOX_IDX,
            _type, self.mbox)]

        # inneficient, but first let's grok it and then
        # let's worry about efficiency.
        # XXX FIXINDEX -- should implement order by in soledad
        return sorted(all_docs, key=lambda item: item.content['uid'])

    def all_msg_iter(self):
        """
        Return an iterator trhough the UIDs of all messages, sorted in
        ascending order.
        """
        all_uids = (doc.content[self.UID_KEY] for doc in
                    self._soledad.get_from_index(
                        SoledadBackedAccount.TYPE_MBOX_IDX,
                        self.TYPE_FLAGS_VAL, self.mbox))
        return (u for u in sorted(all_uids))

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        count = self._soledad.get_count_from_index(
            SoledadBackedAccount.TYPE_MBOX_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox)
        return count

    # unseen messages

    def unseen_iter(self):
        """
        Get an iterator for the message UIDs with no `seen` flag
        for this mailbox.

        :return: iterator through unseen message doc UIDs
        :rtype: iterable
        """
        return (doc.content[self.UID_KEY] for doc in
                self._soledad.get_from_index(
                    SoledadBackedAccount.TYPE_MBOX_SEEN_IDX,
                    self.TYPE_FLAGS_VAL, self.mbox, '0'))

    def count_unseen(self):
        """
        Count all messages with the `Unseen` flag.

        :returns: count
        :rtype: int
        """
        count = self._soledad.get_count_from_index(
            SoledadBackedAccount.TYPE_MBOX_SEEN_IDX,
            self.TYPE_FLAGS_VAL, self.mbox, '0')
        return count

    def get_unseen(self):
        """
        Get all messages with the `Unseen` flag

        :returns: a list of LeapMessages
        :rtype: list
        """
        return [LeapMessage(self._soledad, docid, self.mbox)
                for docid in self.unseen_iter()]

    # recent messages

    def recent_iter(self):
        """
        Get an iterator for the message docs with `recent` flag.

        :return: iterator through recent message docs
        :rtype: iterable
        """
        return (doc.content[self.UID_KEY] for doc in
                self._soledad.get_from_index(
                    SoledadBackedAccount.TYPE_MBOX_RECT_IDX,
                    self.TYPE_FLAGS_VAL, self.mbox, '1'))

    def get_recent(self):
        """
        Get all messages with the `Recent` flag.

        :returns: a list of LeapMessages
        :rtype: list
        """
        return [LeapMessage(self._soledad, docid, self.mbox)
                for docid in self.recent_iter()]

    def count_recent(self):
        """
        Count all messages with the `Recent` flag.

        :returns: count
        :rtype: int
        """
        count = self._soledad.get_count_from_index(
            SoledadBackedAccount.TYPE_MBOX_RECT_IDX,
            self.TYPE_FLAGS_VAL, self.mbox, '1')
        return count

    def __len__(self):
        """
        Returns the number of messages on this mailbox.

        :rtype: int
        """
        return self.count()

    def __iter__(self):
        """
        Returns an iterator over all messages.

        :returns: iterator of dicts with content for all messages.
        :rtype: iterable
        """
        return (LeapMessage(self._soledad, docuid, self.mbox)
                for docuid in self.all_msg_iter())

    def __repr__(self):
        """
        Representation string for this object.
        """
        return u"<MessageCollection: mbox '%s' (%s)>" % (
            self.mbox, self.count())

    # XXX should implement __eq__ also !!! --- use a hash
    # of content for that, will be used for dedup.
