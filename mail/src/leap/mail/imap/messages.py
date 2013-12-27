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
from leap.common.decorators import memoized_method
from leap.common.mail import get_email_charset
from leap.mail.decorators import deferred
from leap.mail.imap.index import IndexedDB
from leap.mail.imap.fields import fields, WithMsgFields
from leap.mail.imap.parser import MailParser, MBoxParser
from leap.mail.messageflow import IMessageConsumer, MessageProducer

logger = logging.getLogger(__name__)


def first(things):
    """
    Return the head of a collection.
    """
    try:
        return things[0]
    except (IndexError, TypeError):
        return None


class MessageBody(object):
    """
    IMessagePart implementor for the main
    body of a multipart message.

    Excusatio non petita: see the interface documentation.
    """

    implements(imap4.IMessagePart)

    def __init__(self, fdoc, bdoc):
        self._fdoc = fdoc
        self._bdoc = bdoc

    def getSize(self):
        return len(self._bdoc.content[fields.BODY_KEY])

    def getBodyFile(self):
        fd = StringIO.StringIO()

        if self._bdoc:
            body = self._bdoc.content[fields.BODY_KEY]
        else:
            body = ""
        charset = self._get_charset(body)
        try:
            body = body.encode(charset)
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            logger.error("Unicode error {0}".format(e))
            body = body.encode(charset, 'replace')
        fd.write(body)
        fd.seek(0)
        return fd

    @memoized_method
    def _get_charset(self, stuff):
        return get_email_charset(unicode(stuff))

    def getHeaders(self, negate, *names):
        return {}

    def isMultipart(self):
        return False

    def getSubPart(self, part):
        return None


class MessageAttachment(object):

    implements(imap4.IMessagePart)

    def __init__(self, msg):
        """
        Initializes the messagepart with a Message instance.
        :param msg: a message instance
        :type msg: Message
        """
        self._msg = msg

    def getSize(self):
        """
        Return the total size, in octets, of this message part.

        :return: size of the message, in octets
        :rtype: int
        """
        if not self._msg:
            return 0
        return len(self._msg.as_string())

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        fd = StringIO.StringIO()
        if self._msg:
            body = self._msg.get_payload()
        else:
            logger.debug("Empty message!")
            body = ""

        # XXX should only do the dance if we're sure it's
        # content/text-plain!!!
        #charset = self._get_charset(body)
        #try:
            #body = body.encode(charset)
        #except (UnicodeEncodeError, UnicodeDecodeError) as e:
            #logger.error("Unicode error {0}".format(e))
            #body = body.encode(charset, 'replace')
        fd.write(body)
        fd.seek(0)
        return fd

    @memoized_method
    def _get_charset(self, stuff):
        # TODO put in a common class with LeapMessage
        """
        Gets (guesses?) the charset of a payload.

        :param stuff: the stuff to guess about.
        :type stuff: basestring
        :returns: charset
        """
        # XXX existential doubt 1. wouldn't be smarter to
        # peek into the mail headers?
        # XXX existential doubt 2. shouldn't we make the scope
        # of the decorator somewhat more persistent?
        # ah! yes! and put memory bounds.
        return get_email_charset(unicode(stuff))

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
        if not self._msg:
            return {}
        headers = dict(self._msg.items())
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
        return self._msg.is_multipart()

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
        return self._msg.get_payload()


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

        self.__chash = None
        self.__bdoc = None

    @property
    def _fdoc(self):
        """
        An accessor to the flags document.
        """
        if all(map(bool, (self._uid, self._mbox))):
            fdoc = self._get_flags_doc()
            if fdoc:
                self.__chash = fdoc.content.get(
                    fields.CONTENT_HASH_KEY, None)
            return fdoc

    @property
    def _chash(self):
        """
        An accessor to the content hash for this message.
        """
        if not self._fdoc:
            return None
        if not self.__chash and self._fdoc:
            self.__chash = self._fdoc.content.get(
                fields.CONTENT_HASH_KEY, None)
        return self.__chash

    @property
    def _hdoc(self):
        """
        An accessor to the headers document.
        """
        return self._get_headers_doc()

    @property
    def _bdoc(self):
        """
        An accessor to the body document.
        """
        if not self.__bdoc:
            self.__bdoc = self._get_body_doc()
        return self.__bdoc

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
        fdoc = self._fdoc
        if fdoc:
            flags = fdoc.content.get(self.FLAGS_KEY, None)
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
        return str(self._hdoc.content.get(self.DATE_KEY, ''))

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
        bdoc = self._bdoc
        if bdoc:
            body = self._bdoc.content.get(self.BODY_KEY, "")
        else:
            body = ""

        charset = self._get_charset(body)
        try:
            body = body.encode(charset)
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            logger.error("Unicode error {0}".format(e))
            body = body.encode(charset, 'replace')
        fd.write(body)
        fd.seek(0)
        return fd

    @memoized_method
    def _get_charset(self, stuff):
        """
        Gets (guesses?) the charset of a payload.

        :param stuff: the stuff to guess about.
        :type stuff: basestring
        :returns: charset
        """
        # XXX existential doubt 1. wouldn't be smarter to
        # peek into the mail headers?
        # XXX existential doubt 2. shouldn't we make the scope
        # of the decorator somewhat more persistent?
        # ah! yes! and put memory bounds.
        return get_email_charset(unicode(stuff))

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        size = None
        if self._fdoc:
            size = self._fdoc.content.get(self.SIZE_KEY, False)
        else:
            logger.warning("No FLAGS doc for %s:%s" % (self._mbox,
                                                       self._uid))
        if not size:
            # XXX fallback, should remove when all migrated.
            size = self.getBodyFile().len
        return size

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
        if not headers:
            return {'content-type': ''}
        names = map(lambda s: s.upper(), names)
        if negate:
            cond = lambda key: key.upper() not in names
        else:
            cond = lambda key: key.upper() in names

        head = copy.deepcopy(dict(headers.items()))

            # twisted imap server expects headers to be lowercase
        head = dict(
            map(str, (key, value)) if key.lower() != "content-type"
            else map(str, (key.lower(), value))
            for (key, value) in head.items())

        # unpack and filter original dict by negate-condition
        filter_by_cond = [(key, val) for key, val in head.items() if cond(key)]
        return dict(filter_by_cond)

    def _get_headers(self):
        """
        Return the headers dict for this message.
        """
        if self._hdoc is not None:
            return self._hdoc.content.get(self.HEADERS_KEY, {})
        else:
            logger.warning(
                "No HEADERS doc for msg %s:%s" % (
                    self._mbox,
                    self._uid))

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        if self._fdoc:
            return self._fdoc.content.get(self.MULTIPART_KEY, False)
        else:
            logger.warning(
                "No FLAGS doc for msg %s:%s" % (
                    self.mbox,
                    self.uid))

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
        logger.debug("Getting subpart: %s" % part)
        if not self.isMultipart():
            raise TypeError

        if part == 0:
            # Let's get the first part, which
            # is really the body.
            return MessageBody(self._fdoc, self._bdoc)

        attach_doc = self._get_attachment_doc(part)
        if not attach_doc:
            # so long and thanks for all the fish
            logger.debug("...not today")
            raise IndexError
        msg_part = self._get_parsed_msg(attach_doc.content[self.RAW_KEY])
        return MessageAttachment(msg_part)

    #
    # accessors
    #

    def _get_flags_doc(self):
        """
        Return the document that keeps the flags for this
        message.
        """
        flag_docs = self._soledad.get_from_index(
            fields.TYPE_MBOX_UID_IDX,
            fields.TYPE_FLAGS_VAL, self._mbox, str(self._uid))
        return first(flag_docs)

    def _get_headers_doc(self):
        """
        Return the document that keeps the headers for this
        message.
        """
        head_docs = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_HEADERS_VAL, str(self._chash))
        return first(head_docs)

    def _get_body_doc(self):
        """
        Return the document that keeps the body for this
        message.
        """
        body_docs = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_MESSAGE_VAL, str(self._chash))
        return first(body_docs)

    def _get_num_parts(self):
        """
        Return the number of parts for a multipart message.
        """
        if not self.isMultipart():
            raise TypeError(
                "Tried to get num parts in a non-multipart message")
        if not self._hdoc:
            return None
        return self._hdoc.content.get(fields.NUM_PARTS_KEY, 2)

    def _get_attachment_doc(self, part):
        """
        Return the document that keeps the headers for this
        message.

        :param part: the part number for the multipart message.
        :type part: int
        """
        if not self._hdoc:
            return None
        try:
            phash = self._hdoc.content[self.PARTS_MAP_KEY][str(part)]
        except KeyError:
            # this is the remnant of a debug session until
            # I found that the index is actually a string...
            # It should be safe to just raise the KeyError now,
            # but leaving it here while the blood is fresh...
            logger.warning("We expected a phash in the "
                           "index %s, but noone found" % (part, ))
            logger.debug(self._hdoc.content[self.PARTS_MAP_KEY])
            return None
        attach_docs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_ATTACHMENT_VAL, str(phash))

        # The following is true for the fist owner.
        # We could use this relationship to flag the "owner"
        # and orphan when we delete it.

        #attach_docs = self._soledad.get_from_index(
            #fields.TYPE_C_HASH_PART_IDX,
            #fields.TYPE_ATTACHMENT_VAL, str(self._chash), str(part))
        return first(attach_docs)

    def _get_raw_msg(self):
        """
        Return the raw msg.
        :rtype: basestring
        """
        # TODO deprecate this.
        return self._bdoc.content.get(self.RAW_KEY, '')

    def __getitem__(self, key):
        """
        Return an item from the content of the flags document,
        for convenience.

        :param key: The key
        :type key: str

        :return: The content value indexed by C{key} or None
        :rtype: str
        """
        return self._fdoc.content.get(key, None)

    # setters

    # XXX to be used in the messagecopier interface?!

    def set_uid(self, uid):
        """
        Set new uid for this message.

        :param uid: the new uid
        :type uid: basestring
        """
        # XXX dangerous! lock?
        self._uid = uid
        d = self._fdoc
        d.content[self.UID_KEY] = uid
        self._soledad.put_doc(d)

    def set_mbox(self, mbox):
        """
        Set new mbox for this message.

        :param mbox: the new mbox
        :type mbox: basestring
        """
        # XXX dangerous! lock?
        self._mbox = mbox
        d = self._fdoc
        d.content[self.MBOX_KEY] = mbox
        self._soledad.put_doc(d)

    # destructor

    @deferred
    def remove(self):
        """
        Remove all docs associated with this message.
        """
        # XXX this would ve more efficient if we can just pass
        # a sequence of uids.

        # XXX For the moment we are only removing the flags and headers
        # docs. The rest we leave there polluting your hard disk,
        # until we think about a good way of deorphaning.
        # Maybe a crawler of unreferenced docs.

        fd = self._get_flags_doc()
        hd = self._get_headers_doc()
        #bd = self._get_body_doc()
        #docs = [fd, hd, bd]

        docs = [fd, hd]

        #for pn in range(self._get_num_parts()[1:]):
            #ad = self._get_attachment_doc(pn)
            #docs.append(ad)

        for d in filter(None, docs):
            self._soledad.delete_doc(d)

    def does_exist(self):
        """
        Return True if there is actually a flags message for this
        UID and mbox.
        """
        return self._fdoc is not None


SoledadWriterPayload = namedtuple(
    'SoledadWriterPayload', ['mode', 'payload'])

SoledadWriterPayload.CREATE = 1
SoledadWriterPayload.PUT = 2
SoledadWriterPayload.BODY_CREATE = 3
SoledadWriterPayload.ATTACHMENT_CREATE = 4


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
            call = None
            payload = item.payload

            if item.mode == SoledadWriterPayload.CREATE:
                call = self._soledad.create_doc
            elif item.mode == SoledadWriterPayload.BODY_CREATE:
                if not self._body_does_exist(payload):
                    call = self._soledad.create_doc
            elif item.mode == SoledadWriterPayload.ATTACHMENT_CREATE:
                if not self._attachment_does_exist(payload):
                    call = self._soledad.create_doc
            elif item.mode == SoledadWriterPayload.PUT:
                call = self._soledad.put_doc

            # XXX delete?

            if call:
                # should handle errors
                try:
                    call(item.payload)
                except u1db_errors.RevisionConflict as exc:
                    logger.error("Error: %r" % (exc,))
                    raise exc

            empty = queue.empty()

    """
    Message deduplication.

    We do a query for the content hashes before writing to our beloved
    slcipher backend of Soledad. This means, by now, that:

    1. We will not store the same attachment twice, only the hash of it.
    2. We will not store the same message body twice, only the hash of it.

    The first case is useful if you are always receiving the same old memes
    from unwary friends that still have not discovered that 4chan is the
    generator of the internet. The second will save your day if you have
    initiated session with the same account in two different machines. I also
    wonder why would you do that, but let's respect each other choices, like
    with the religious celebrations, and assume that one day we'll be able
    to run Bitmask in completely free phones. Yes, I mean that, the whole GSM
    Stack.
    """

    def _body_does_exist(self, doc):
        """
        Check whether we already have a body payload with this hash in our
        database.

        :param doc: tentative body document
        :type doc: dict
        :returns: True if that happens, False otherwise.
        """
        if not doc:
            return False
        chash = doc[fields.CONTENT_HASH_KEY]
        body_docs = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_MESSAGE_VAL, str(chash))
        if not body_docs:
            return False
        if len(body_docs) != 1:
            logger.warning("Found more than one copy of chash %s!"
                           % (chash,))
        logger.debug("Found body doc with that hash! Skipping save!")
        return True

    def _attachment_does_exist(self, doc):
        """
        Check whether we already have an attachment payload with this hash
        in our database.

        :param doc: tentative body document
        :type doc: dict
        :returns: True if that happens, False otherwise.
        """
        if not doc:
            return False
        phash = doc[fields.PAYLOAD_HASH_KEY]
        attach_docs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_ATTACHMENT_VAL, str(phash))
        if not attach_docs:
            return False

        if len(attach_docs) != 1:
            logger.warning("Found more than one copy of phash %s!"
                           % (phash,))
        logger.debug("Found attachment doc with that hash! Skipping save!")
        return True


class MessageCollection(WithMsgFields, IndexedDB, MailParser, MBoxParser):
    """
    A collection of messages, surprisingly.

    It is tied to a selected mailbox name that is passed to constructor.
    Implements a filter query over the messages contained in a soledad
    database.
    """
    # XXX this should be able to produce a MessageSet methinks
    # could validate these kinds of objects turning them
    # into a template for the class.
    FLAGS_DOC = "FLAGS"
    HEADERS_DOC = "HEADERS"
    ATTACHMENT_DOC = "ATTACHMENT"
    BODY_DOC = "BODY"

    templates = {

        FLAGS_DOC: {
            fields.TYPE_KEY: fields.TYPE_FLAGS_VAL,
            fields.UID_KEY: 1,
            fields.MBOX_KEY: fields.INBOX_VAL,

            fields.SEEN_KEY: False,
            fields.RECENT_KEY: True,
            fields.FLAGS_KEY: [],
            fields.MULTIPART_KEY: False,
            fields.SIZE_KEY: 0
        },

        HEADERS_DOC: {
            fields.TYPE_KEY: fields.TYPE_HEADERS_VAL,
            fields.CONTENT_HASH_KEY: "",

            fields.HEADERS_KEY: {},
            fields.NUM_PARTS_KEY: 0,
            fields.PARTS_MAP_KEY: {},
            fields.DATE_KEY: "",
            fields.SUBJECT_KEY: ""
        },

        ATTACHMENT_DOC: {
            fields.TYPE_KEY: fields.TYPE_ATTACHMENT_VAL,
            fields.PART_NUMBER_KEY: 0,
            fields.CONTENT_HASH_KEY:  "",
            fields.PAYLOAD_HASH_KEY: "",

            fields.RAW_KEY: ""
        },

        BODY_DOC: {
            fields.TYPE_KEY: fields.TYPE_MESSAGE_VAL,
            fields.CONTENT_HASH_KEY: "",

            fields.BODY_KEY: "",

            # this should not be needed,
            # but let's keep the raw msg for some time
            # until we are sure we can reconstruct
            # the original msg from our disection.
            fields.RAW_KEY: "",

        }
    }

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

    def _get_empty_doc(self, _type=FLAGS_DOC):
        """
        Returns an empty doc for storing different message parts.
        Defaults to returning a template for a flags document.
        :return: a dict with the template
        :rtype: dict
        """
        if not _type in self.templates.keys():
            raise TypeError("Improper type passed to _get_empty_doc")
        return copy.deepcopy(self.templates[_type])

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

        # docs for flags, headers, and body
        fd, hd, bd = map(
            lambda t: self._get_empty_doc(t),
            (self.FLAGS_DOC, self.HEADERS_DOC, self.BODY_DOC))

        msg = self._get_parsed_msg(raw)
        headers = dict(msg)
        raw_str = msg.as_string()
        chash = self._get_hash(msg)
        multi = msg.is_multipart()

        attaches = []
        inner_parts = []

        if multi:
            # XXX should walk down recursively
            # in a better way.  but fixing this quick
            # to have an rc.
            # XXX should pick the content-type in txt
            body = first(msg.get_payload()).get_payload()
            if isinstance(body, list):
                # allowing one nesting level for now...
                body, rest = body[0].get_payload(), body[1:]
                for p in rest:
                    inner_parts.append(p)
        else:
            body = msg.get_payload()
        logger.debug("adding msg (multipart:%s)" % multi)

        # flags doc ---------------------------------------
        fd[self.MBOX_KEY] = self.mbox
        fd[self.UID_KEY] = uid
        fd[self.CONTENT_HASH_KEY] = chash
        fd[self.MULTIPART_KEY] = multi
        fd[self.SIZE_KEY] = len(raw_str)
        if flags:
            fd[self.FLAGS_KEY] = map(self._stringify, flags)
            fd[self.SEEN_KEY] = self.SEEN_FLAG in flags
            fd[self.RECENT_KEY] = self.RECENT_FLAG in flags

        # headers doc ----------------------------------------
        hd[self.CONTENT_HASH_KEY] = chash
        hd[self.HEADERS_KEY] = headers
        if not subject and self.SUBJECT_FIELD in headers:
            hd[self.SUBJECT_KEY] = headers[self.SUBJECT_FIELD]
        else:
            hd[self.SUBJECT_KEY] = subject
        if not date and self.DATE_FIELD in headers:
            hd[self.DATE_KEY] = headers[self.DATE_FIELD]
        else:
            hd[self.DATE_KEY] = date
        if multi:
            hd[self.NUM_PARTS_KEY] = len(msg.get_payload())

        # body doc
        bd[self.CONTENT_HASH_KEY] = chash
        bd[self.BODY_KEY] = body
        # in an ideal world, we would not need to save a copy of the
        # raw message. But we'll keep it until we can be sure that
        # we can rebuild the original message from the parts.
        bd[self.RAW_KEY] = raw_str

        docs = [fd, hd]

        # attachment docs
        if multi:
            outer_parts = msg.get_payload()
            parts = outer_parts + inner_parts

            # skip first part, we already got it in body
            to_attach = ((i, m) for i, m in enumerate(parts) if i > 0)
            for index, part_msg in to_attach:
                att_doc = self._get_empty_doc(self.ATTACHMENT_DOC)
                att_doc[self.PART_NUMBER_KEY] = index
                att_doc[self.CONTENT_HASH_KEY] = chash
                phash = self._get_hash(part_msg)
                att_doc[self.PAYLOAD_HASH_KEY] = phash
                att_doc[self.RAW_KEY] = part_msg.as_string()

                # keep a pointer to the payload hash in the
                # headers doc, under the parts_map
                hd[self.PARTS_MAP_KEY][str(index)] = phash
                attaches.append(att_doc)

        # Saving ... -------------------------------
        # ok, there we go...
        logger.debug('enqueuing message docs for write')
        ptuple = SoledadWriterPayload

        # first, regular docs: flags and headers
        for doc in docs:
            self.soledad_writer.put(ptuple(
                mode=ptuple.CREATE, payload=doc))
        # second, try to create body doc.
        self.soledad_writer.put(ptuple(
            mode=ptuple.BODY_CREATE, payload=bd))
        # and last, but not least, try to create
        # attachment docs if not already there.
        for at in attaches:
            self.soledad_writer.put(ptuple(
                mode=ptuple.ATTACHMENT_CREATE, payload=at))

    def remove(self, msg):
        """
        Removes a message.

        :param msg: a  Leapmessage instance
        :type msg: LeapMessage
        """
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
            raise TypeError("Wrong type passed to get_all_docs")

        if sameProxiedObjects(self._soledad, None):
            logger.warning('Tried to get messages but soledad is None!')
            return []

        all_docs = [doc for doc in self._soledad.get_from_index(
            fields.TYPE_MBOX_IDX,
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
                        fields.TYPE_MBOX_IDX,
                        fields.TYPE_FLAGS_VAL, self.mbox))
        return (u for u in sorted(all_uids))

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        count = self._soledad.get_count_from_index(
            fields.TYPE_MBOX_IDX,
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
                    fields.TYPE_MBOX_SEEN_IDX,
                    fields.TYPE_FLAGS_VAL, self.mbox, '0'))

    def count_unseen(self):
        """
        Count all messages with the `Unseen` flag.

        :returns: count
        :rtype: int
        """
        count = self._soledad.get_count_from_index(
            fields.TYPE_MBOX_SEEN_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox, '0')
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
                    fields.TYPE_MBOX_RECT_IDX,
                    fields.TYPE_FLAGS_VAL, self.mbox, '1'))

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
            fields.TYPE_MBOX_RECT_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox, '1')
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

    # XXX should implement __eq__ also !!!
    # --- use the content hash for that, will be used for dedup.
