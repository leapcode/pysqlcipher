# -*- coding: utf-8 -*-
# imap/messages.py
# Copyright (C) 2013-2015 LEAP
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
IMAPMessage and IMAPMessageCollection.
"""
import logging
# import StringIO
from twisted.mail import imap4
from zope.interface import implements

from leap.common.check import leap_assert, leap_assert_type
from leap.common.decorators import memoized_method
from leap.common.mail import get_email_charset

from leap.mail.utils import find_charset

from leap.mail.imap.messageparts import MessagePart
# from leap.mail.imap.messagepargs import MessagePartDoc

logger = logging.getLogger(__name__)

# TODO ------------------------------------------------------------

# [ ] Add ref to incoming message during add_msg.
# [ ] Delete incoming mail only after successful write.


class IMAPMessage(object):
    """
    The main representation of a message.
    """

    implements(imap4.IMessage)

    def __init__(self, message):
        """
        Initializes a LeapMessage.
        """
        self.message = message

    # IMessage implementation

    def getUID(self):
        """
        Retrieve the unique identifier associated with this Message.

        :return: uid for this message
        :rtype: int
        """
        return self.message.get_uid()

    def getFlags(self):
        """
        Retrieve the flags associated with this Message.

        :return: The flags, represented as strings
        :rtype: tuple
        """
        return self.message.get_flags()

    # setFlags not in the interface spec but we use it with store command.

    # XXX if we can move it to a collection method, we don't need to pass
    # collection to the IMAPMessage

    # lookup method? IMAPMailbox?

    #def setFlags(self, flags, mode):
        #"""
        #Sets the flags for this message
#
        #:param flags: the flags to update in the message.
        #:type flags: tuple of str
        #:param mode: the mode for setting. 1 is append, -1 is remove, 0 set.
        #:type mode: int
        #"""
        #leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        # XXX
        # return new flags
        # map to str
        #self.message.set_flags(flags, mode)
        #self.collection.update_flags(self.message, flags, mode)

    def getInternalDate(self):
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
        return self.message.get_internal_date()

    #
    # IMessagePart
    #

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        # TODO refactor with getBodyFile in MessagePart

        #body = bdoc_content.get(self.RAW_KEY, "")
        #content_type = bdoc_content.get('content-type', "")
        #charset = find_charset(content_type)
        #if charset is None:
            #charset = self._get_charset(body)
        #try:
            #if isinstance(body, unicode):
                #body = body.encode(charset)
        #except UnicodeError as exc:
            #logger.error(
                #"Unicode error, using 'replace'. {0!r}".format(exc))
            #logger.debug("Attempted to encode with: %s" % charset)
            #body = body.encode(charset, 'replace')
        #finally:
            #return write_fd(body)

        return self.message.get_body_file()

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        return self.message.get_size()

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
        # TODO split in smaller methods -- format_headers()?
        # XXX refactor together with MessagePart method

        headers = self.message.get_headers()

        # XXX keep this in the imap imessage implementation,
        # because the server impl. expects content-type to be present.
        if not headers:
            logger.warning("No headers found")
            return {str('content-type'): str('')}

        names = map(lambda s: s.upper(), names)
        if negate:
            cond = lambda key: key.upper() not in names
        else:
            cond = lambda key: key.upper() in names

        if isinstance(headers, list):
            headers = dict(headers)

        # default to most likely standard
        charset = find_charset(headers, "utf-8")
        headers2 = dict()
        for key, value in headers.items():
            # twisted imap server expects *some* headers to be lowercase
            # We could use a CaseInsensitiveDict here...
            if key.lower() == "content-type":
                key = key.lower()

            if not isinstance(key, str):
                key = key.encode(charset, 'replace')
            if not isinstance(value, str):
                value = value.encode(charset, 'replace')

            if value.endswith(";"):
                # bastards
                value = value[:-1]

            # filter original dict by negate-condition
            if cond(key):
                headers2[key] = value
        return headers2

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        return self.message.is_multipart()

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
        return self.message.get_subpart(part)


class IMAPMessageCollection(object):
    """
    A collection of messages, surprisingly.

    It is tied to a selected mailbox name that is passed to its constructor.
    Implements a filter query over the messages contained in a soledad
    database.
    """

    messageklass = IMAPMessage

    # TODO
    # [ ] Add RECENT flags docs to mailbox-doc attributes (list-of-uids)
    # [ ] move Query for all the headers documents to Collection

    # TODO this should be able to produce a MessageSet methinks
    # TODO --- reimplement, review and prune documentation below.

    FLAGS_DOC = "FLAGS"
    HEADERS_DOC = "HEADERS"
    CONTENT_DOC = "CONTENT"
    """
    RECENT_DOC is a document that stores a list of the UIDs
    with the recent flag for this mailbox. It deserves a special treatment
    because:
    (1) it cannot be set by the user
    (2) it's a flag that we set inmediately after a fetch, which is quite
        often.
    (3) we need to be able to set/unset it in batches without doing a single
        write for each element in the sequence.
    """
    RECENT_DOC = "RECENT"
    """
    HDOCS_SET_DOC is a document that stores a set of the Document-IDs
    (the u1db index) for all the headers documents for a given mailbox.
    We use it to prefetch massively all the headers for a mailbox.
    This is the second massive query, after fetching all the FLAGS,  that
    a typical IMAP MUA will do in a case where we do not have local disk cache.
    """
    HDOCS_SET_DOC = "HDOCS_SET"

    def __init__(self, collection):
        """
        Constructor for IMAPMessageCollection.

        :param collection: an instance of a MessageCollection
        :type collection: MessageCollection
        """
        leap_assert(
            collection.is_mailbox_collection(),
            "Need a mailbox name to initialize")
        mbox_name = collection.mbox_name
        leap_assert(mbox_name.strip() != "", "mbox cannot be blank space")
        leap_assert(isinstance(mbox_name, (str, unicode)),
                    "mbox needs to be a string")
        self.collection = collection

        # XXX this has to be done in IMAPAccount
        # (Where the collection must be instantiated and passed to us)
        # self.mbox = normalize_mailbox(mbox)

    @property
    def mbox_name(self):
        """
        Return the string that identifies this mailbox.
        """
        return self.collection.mbox_name

    def add_msg(self, raw, flags=None, date=None):
        """
        Creates a new message document.

        :param raw: the raw message
        :type raw: str

        :param flags: flags
        :type flags: list

        :param date: the received date for the message
        :type date: str

        :return: a deferred that will be fired with the message
                 uid when the adding succeed.
        :rtype: deferred
        """
        if flags is None:
            flags = tuple()
        leap_assert_type(flags, tuple)
        return self.collection.add_msg(raw, flags, date)

    def get_msg_by_uid(self, uid, absolute=True):
        """
        Retrieves a IMAPMessage by UID.
        This is used primarity in the Mailbox fetch and store methods.

        :param uid: the message uid to query by
        :type uid: int

        :rtype: IMAPMessage
        """
        def make_imap_msg(msg):
            kls = self.messageklass
            # TODO --- remove ref to collection
            return kls(msg, self.collection)

        d = self.collection.get_msg_by_uid(uid, absolute=absolute)
        d.addCalback(make_imap_msg)
        return d


    # TODO -- move this to collection too
    # Used for the Search (Drafts) queries?
    def _get_uid_from_msgid(self, msgid):
        """
        Return a UID for a given message-id.

        It first gets the headers-doc for that msg-id, and
        it found it queries the flags doc for the current mailbox
        for the matching content-hash.

        :return: A UID, or None
        """
        return self._get_uid_from_msgidCb(msgid)

    # TODO handle deferreds
    def set_flags(self, messages, flags, mode):
        """
        Set flags for a sequence of messages.

        :param mbox: the mbox this message belongs to
        :type mbox: str or unicode
        :param messages: the messages to iterate through
        :type messages: sequence
        :flags: the flags to be set
        :type flags: tuple
        :param mode: the mode for setting. 1 is append, -1 is remove, 0 set.
        :type mode: int
        :param observer: a deferred that will be called with the dictionary
                         mapping UIDs to flags after the operation has been
                         done.
        :type observer: deferred
        """
        getmsg = self.get_msg_by_uid

        def set_flags(uid, flags, mode):
            msg = getmsg(uid)
            if msg is not None:
                # XXX IMAPMessage needs access to the collection
                # to be able to set flags. Better if we make use
                # of collection... here.
                return uid, msg.setFlags(flags, mode)

        setted_flags = [set_flags(uid, flags, mode) for uid in messages]
        result = dict(filter(None, setted_flags))
        # XXX return gatherResults or something
        return result

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        return self.collection.count()

    # headers query

    def all_headers(self):
        """
        Return a dict with all the header documents for this
        mailbox.

        :rtype: dict
        """
        # Use self.collection.mbox_indexer
        # and derive all the doc_ids for the hdocs
        raise NotImplementedError()

    # unseen messages

    def unseen_iter(self):
        """
        Get an iterator for the message UIDs with no `seen` flag
        for this mailbox.

        :return: iterator through unseen message doc UIDs
        :rtype: iterable
        """
        raise NotImplementedError()

    def count_unseen(self):
        """
        Count all messages with the `Unseen` flag.

        :returns: count
        :rtype: int
        """
        return len(list(self.unseen_iter()))

    def get_unseen(self):
        """
        Get all messages with the `Unseen` flag

        :returns: a list of LeapMessages
        :rtype: list
        """
        raise NotImplementedError()
        #return [self.messageklass(self._soledad, doc_id, self.mbox)
                #for doc_id in self.unseen_iter()]

    # recent messages

    def count_recent(self):
        """
        Count all messages with the `Recent` flag.
        It just retrieves the length of the recent_flags set,
        which is stored in a specific type of document for
        this collection.

        :returns: count
        :rtype: int
        """
        raise NotImplementedError()

    # magic

    def __len__(self):
        """
        Returns the number of messages on this mailbox.
        :rtype: int
        """
        return self.count()

    def __repr__(self):
        """
        Representation string for this object.
        """
        return u"<IMAPMessageCollection: mbox '%s' (%s)>" % (
            self.mbox_name, self.count())

    # TODO implement __iter__ ?
