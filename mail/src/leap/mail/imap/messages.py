# -*- coding: utf-8 -*-
# messages.py
# Copyright (C) 2013, 2014 LEAP
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
import threading
import StringIO

from collections import defaultdict
from functools import partial

from twisted.mail import imap4
from twisted.internet import reactor
from zope.interface import implements
from zope.proxy import sameProxiedObjects

from leap.common.check import leap_assert, leap_assert_type
from leap.common.decorators import memoized_method
from leap.common.mail import get_email_charset
from leap.mail.adaptors import soledad_indexes as indexes
from leap.mail.constants import INBOX_NAME
from leap.mail.utils import find_charset, empty
from leap.mail.imap.index import IndexedDB
from leap.mail.imap.fields import fields, WithMsgFields
from leap.mail.imap.messageparts import MessagePart, MessagePartDoc
from leap.mail.imap.parser import MBoxParser

logger = logging.getLogger(__name__)

# TODO ------------------------------------------------------------

# [ ] Add ref to incoming message during add_msg
# [ ] Add linked-from info.
#     * Need a new type of documents: linkage info.
#     * HDOCS are linked from FDOCs (ref to chash)
#     * CDOCS are linked from HDOCS (ref to chash)

# [ ] Delete incoming mail only after successful write!
# [ ] Remove UID from syncable db. Store only those indexes locally.


def try_unique_query(curried):
    """
    Try to execute a query that is expected to have a
    single outcome, and log a warning if more than one document found.

    :param curried: a curried function
    :type curried: callable
    """
    # XXX FIXME ---------- convert to deferreds
    leap_assert(callable(curried), "A callable is expected")
    try:
        query = curried()
        if query:
            if len(query) > 1:
                # TODO we could take action, like trigger a background
                # process to kill dupes.
                name = getattr(curried, 'expected', 'doc')
                logger.warning(
                    "More than one %s found for this mbox, "
                    "we got a duplicate!!" % (name,))
            return query.pop()
        else:
            return None
    except Exception as exc:
        logger.exception("Unhandled error %r" % exc)


# FIXME remove-me
#fdoc_locks = defaultdict(lambda: defaultdict(lambda: threading.Lock()))


class IMAPMessage(fields, MBoxParser):
    """
    The main representation of a message.
    """

    implements(imap4.IMessage)

    def __init__(self, soledad, uid, mbox):
        """
        Initializes a LeapMessage.

        :param soledad: a Soledad instance
        :type soledad: Soledad
        :param uid: the UID for the message.
        :type uid: int or basestring
        :param mbox: the mbox this message belongs to
        :type mbox: str or unicode
        :param collection: a reference to the parent collection object
        :type collection: MessageCollection
        :param container: a IMessageContainer implementor instance
        :type container: IMessageContainer
        """
        self._soledad = soledad
        self._uid = int(uid) if uid is not None else None
        self._mbox = self._parse_mailbox_name(mbox)

        self.__chash = None
        self.__bdoc = None

    # TODO collection and container are deprecated.

    # TODO move to adaptor

    #@property
    #def fdoc(self):
        #"""
        #An accessor to the flags document.
        #"""
        #if all(map(bool, (self._uid, self._mbox))):
            #fdoc = None
            #if self._container is not None:
                #fdoc = self._container.fdoc
            #if not fdoc:
                #fdoc = self._get_flags_doc()
            #if fdoc:
                #fdoc_content = fdoc.content
                #self.__chash = fdoc_content.get(
                    #fields.CONTENT_HASH_KEY, None)
            #return fdoc
#
    #@property
    #def hdoc(self):
        #"""
        #An accessor to the headers document.
        #"""
        #container = self._container
        #if container is not None:
            #hdoc = self._container.hdoc
            #if hdoc and not empty(hdoc.content):
                #return hdoc
        #hdoc = self._get_headers_doc()
#
        #if container and not empty(hdoc.content):
            # mem-cache it
            #hdoc_content = hdoc.content
            #chash = hdoc_content.get(fields.CONTENT_HASH_KEY)
            #hdocs = {chash: hdoc_content}
            #container.memstore.load_header_docs(hdocs)
        #return hdoc
#
    #@property
    #def chash(self):
        #"""
        #An accessor to the content hash for this message.
        #"""
        #if not self.fdoc:
            #return None
        #if not self.__chash and self.fdoc:
            #self.__chash = self.fdoc.content.get(
                #fields.CONTENT_HASH_KEY, None)
        #return self.__chash

    #@property
    #def bdoc(self):
        #"""
        #An accessor to the body document.
        #"""
        #if not self.hdoc:
            #return None
        #if not self.__bdoc:
            #self.__bdoc = self._get_body_doc()
        #return self.__bdoc

    # IMessage implementation

    def getUID(self):
        """
        Retrieve the unique identifier associated with this Message.

        :return: uid for this message
        :rtype: int
        """
        # TODO ----> return lookup in local sqlcipher table.
        return self._uid

    # --------------------------------------------------------------
    # TODO -- from here on, all the methods should be proxied to the
    # instance of leap.mail.mail.Message

    def getFlags(self):
        """
        Retrieve the flags associated with this Message.

        :return: The flags, represented as strings
        :rtype: tuple
        """
        uid = self._uid

        flags = set([])
        fdoc = self.fdoc
        if fdoc:
            flags = set(fdoc.content.get(self.FLAGS_KEY, None))

        msgcol = self._collection

        # We treat the recent flag specially: gotten from
        # a mailbox-level document.
        if msgcol and uid in msgcol.recent_flags:
            flags.add(fields.RECENT_FLAG)
        if flags:
            flags = map(str, flags)
        return tuple(flags)

    # setFlags not in the interface spec but we use it with store command.

    def setFlags(self, flags, mode):
        """
        Sets the flags for this message

        :param flags: the flags to update in the message.
        :type flags: tuple of str
        :param mode: the mode for setting. 1 is append, -1 is remove, 0 set.
        :type mode: int
        """
        leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        mbox, uid = self._mbox, self._uid

        APPEND = 1
        REMOVE = -1
        SET = 0

        doc = self.fdoc
        if not doc:
            logger.warning(
                "Could not find FDOC for %r:%s while setting flags!" %
                (mbox, uid))
            return
        current = doc.content[self.FLAGS_KEY]
        if mode == APPEND:
            newflags = tuple(set(tuple(current) + flags))
        elif mode == REMOVE:
            newflags = tuple(set(current).difference(set(flags)))
        elif mode == SET:
            newflags = flags
        new_fdoc = {
            self.FLAGS_KEY: newflags,
            self.SEEN_KEY: self.SEEN_FLAG in newflags,
            self.DEL_KEY: self.DELETED_FLAG in newflags}
        self._collection.memstore.update_flags(mbox, uid, new_fdoc)

        return map(str, newflags)

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
        date = self.hdoc.content.get(fields.DATE_KEY, '')
        return date

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
        def write_fd(body):
            fd.write(body)
            fd.seek(0)
            return fd

        # TODO refactor with getBodyFile in MessagePart

        fd = StringIO.StringIO()

        if self.bdoc is not None:
            bdoc_content = self.bdoc.content
            if empty(bdoc_content):
                logger.warning("No BDOC content found for message!!!")
                return write_fd("")

            body = bdoc_content.get(self.RAW_KEY, "")
            content_type = bdoc_content.get('content-type', "")
            charset = find_charset(content_type)
            if charset is None:
                charset = self._get_charset(body)
            try:
                if isinstance(body, unicode):
                    body = body.encode(charset)
            except UnicodeError as exc:
                logger.error(
                    "Unicode error, using 'replace'. {0!r}".format(exc))
                logger.debug("Attempted to encode with: %s" % charset)
                body = body.encode(charset, 'replace')
            finally:
                return write_fd(body)

        # We are still returning funky characters from here.
        else:
            logger.warning("No BDOC found for message.")
            return write_fd("")

    @memoized_method
    def _get_charset(self, stuff):
        """
        Gets (guesses?) the charset of a payload.

        :param stuff: the stuff to guess about.
        :type stuff: basestring
        :returns: charset
        """
        # XXX shouldn't we make the scope
        # of the decorator somewhat more persistent?
        # ah! yes! and put memory bounds.
        return get_email_charset(stuff)

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        size = None
        if self.fdoc is not None:
            fdoc_content = self.fdoc.content
            size = fdoc_content.get(self.SIZE_KEY, False)
        else:
            logger.warning("No FLAGS doc for %s:%s" % (self._mbox,
                                                       self._uid))
        #if not size:
            # XXX fallback, should remove when all migrated.
            #size = self.getBodyFile().len
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
        # TODO split in smaller methods
        # XXX refactor together with MessagePart method

        headers = self._get_headers()

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

    def _get_headers(self):
        """
        Return the headers dict for this message.
        """
        if self.hdoc is not None:
            hdoc_content = self.hdoc.content
            headers = hdoc_content.get(self.HEADERS_KEY, {})
            return headers

        else:
            logger.warning(
                "No HEADERS doc for msg %s:%s" % (
                    self._mbox,
                    self._uid))

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        if self.fdoc:
            fdoc_content = self.fdoc.content
            is_multipart = fdoc_content.get(self.MULTIPART_KEY, False)
            return is_multipart
        else:
            logger.warning(
                "No FLAGS doc for msg %s:%s" % (
                    self._mbox,
                    self._uid))

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
        try:
            pmap_dict = self._get_part_from_parts_map(part + 1)
        except KeyError:
            raise IndexError
        return MessagePart(self._soledad, pmap_dict)

    #
    # accessors
    #

    def _get_part_from_parts_map(self, part):
        """
        Get a part map from the headers doc

        :raises: KeyError if key does not exist
        :rtype: dict
        """
        if not self.hdoc:
            logger.warning("Tried to get part but no HDOC found!")
            return None

        hdoc_content = self.hdoc.content
        pmap = hdoc_content.get(fields.PARTS_MAP_KEY, {})

        # remember, lads, soledad is using strings in its keys,
        # not integers!
        return pmap[str(part)]

    # XXX moved to memory store
    # move the rest too. ------------------------------------------
    def _get_flags_doc(self):
        """
        Return the document that keeps the flags for this
        message.
        """
        def get_first_if_any(docs):
            result = first(docs)
            return result if result else {}

        d = self._soledad.get_from_index(
            fields.TYPE_MBOX_UID_IDX,
            fields.TYPE_FLAGS_VAL, self._mbox, str(self._uid))
        d.addCallback(get_first_if_any)
        return d

    # TODO move to soledadstore instead of accessing soledad directly
    def _get_headers_doc(self):
        """
        Return the document that keeps the headers for this
        message.
        """
        d = self._soledad.get_from_index(
            fields.TYPE_C_HASH_IDX,
            fields.TYPE_HEADERS_VAL, str(self.chash))
        d.addCallback(lambda docs: first(docs))
        return d

    # TODO move to soledadstore instead of accessing soledad directly
    def _get_body_doc(self):
        """
        Return the document that keeps the body for this
        message.
        """
        # XXX FIXME --- this might need a maybedeferred
        # on the receiving side...
        hdoc_content = self.hdoc.content
        body_phash = hdoc_content.get(
            fields.BODY_KEY, None)
        if not body_phash:
            logger.warning("No body phash for this document!")
            return None

        # XXX get from memstore too...
        # if memstore: memstore.get_phrash
        # memstore should keep a dict with weakrefs to the
        # phash doc...

        if self._container is not None:
            bdoc = self._container.memstore.get_cdoc_from_phash(body_phash)
            if not empty(bdoc) and not empty(bdoc.content):
                return bdoc

        # no memstore, or no body doc found there
        d = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_CONTENT_VAL, str(body_phash))
        d.addCallback(lambda docs: first(docs))
        return d

    def __getitem__(self, key):
        """
        Return an item from the content of the flags document,
        for convenience.

        :param key: The key
        :type key: str

        :return: The content value indexed by C{key} or None
        :rtype: str
        """
        return self.fdoc.content.get(key, None)

    def does_exist(self):
        """
        Return True if there is actually a flags document for this
        UID and mbox.
        """
        return not empty(self.fdoc)


class MessageCollection(WithMsgFields, IndexedDB, MBoxParser):
    """
    A collection of messages, surprisingly.

    It is tied to a selected mailbox name that is passed to its constructor.
    Implements a filter query over the messages contained in a soledad
    database.
    """

    # XXX this should be able to produce a MessageSet methinks
    # could validate these kinds of objects turning them
    # into a template for the class.
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

    templates = {

        # Mailbox Level

        RECENT_DOC: {
            "type": indexes.RECENT,
            "mbox": INBOX_NAME,
            fields.RECENTFLAGS_KEY: [],
        },

        HDOCS_SET_DOC: {
            "type": indexes.HDOCS_SET,
            "mbox": INBOX_NAME,
            fields.HDOCS_SET_KEY: [],
        }


    }

    # Different locks for wrapping both the u1db document getting/setting
    # and the property getting/settting in an atomic operation.

    # TODO --- deprecate ! --- use SoledadDocumentWrapper + locks
    _rdoc_lock = defaultdict(lambda: threading.Lock())
    _rdoc_write_lock = defaultdict(lambda: threading.Lock())
    _rdoc_read_lock = defaultdict(lambda: threading.Lock())
    _rdoc_property_lock = defaultdict(lambda: threading.Lock())

    _initialized = {}

    def __init__(self, mbox=None, soledad=None, memstore=None):
        """
        Constructor for MessageCollection.

        On initialization, we ensure that we have a document for
        storing the recent flags. The nature of this flag make us wanting
        to store the set of the UIDs with this flag at the level of the
        MessageCollection for each mailbox, instead of treating them
        as a property of each message.

        We are passed an instance of MemoryStore, the same for the
        SoledadBackedAccount, that we use as a read cache and a buffer
        for writes.

        :param mbox: the name of the mailbox. It is the name
                     with which we filter the query over the
                     messages database.
        :type mbox: str
        :param soledad: Soledad database
        :type soledad: Soledad instance
        :param memstore: a MemoryStore instance
        :type memstore: MemoryStore
        """
        leap_assert(mbox, "Need a mailbox name to initialize")
        leap_assert(mbox.strip() != "", "mbox cannot be blank space")
        leap_assert(isinstance(mbox, (str, unicode)),
                    "mbox needs to be a string")
        leap_assert(soledad, "Need a soledad instance to initialize")

        # okay, all in order, keep going...

        self.mbox = self._parse_mailbox_name(mbox)

        # XXX get a SoledadStore passed instead
        self._soledad = soledad
        self.memstore = memstore

        self.__rflags = None

        if not self._initialized.get(mbox, False):
            try:
                self.initialize_db()
                # ensure that we have a recent-flags doc
                self._get_or_create_rdoc()
            except Exception:
                logger.debug("Error initializing %r" % (mbox,))
            else:
                self._initialized[mbox] = True

    def _get_empty_doc(self, _type=FLAGS_DOC):
        """
        Returns an empty doc for storing different message parts.
        Defaults to returning a template for a flags document.
        :return: a dict with the template
        :rtype: dict
        """
        if _type not in self.templates.keys():
            raise TypeError("Improper type passed to _get_empty_doc")
        return copy.deepcopy(self.templates[_type])

    def _get_or_create_rdoc(self):
        """
        Try to retrieve the recent-flags doc for this MessageCollection,
        and create one if not found.
        """
        # XXX should move this to memstore too
        with self._rdoc_write_lock[self.mbox]:
            rdoc = self._get_recent_doc_from_soledad()
            if rdoc is None:
                rdoc = self._get_empty_doc(self.RECENT_DOC)
                if self.mbox != fields.INBOX_VAL:
                    rdoc[fields.MBOX_KEY] = self.mbox
                self._soledad.create_doc(rdoc)

    # --------------------------------------------------------------------

    # -----------------------------------------------------------------------

    def _fdoc_already_exists(self, chash):
        """
        Check whether we can find a flags doc for this mailbox with the
        given content-hash. It enforces that we can only have the same maessage
        listed once for a a given mailbox.

        :param chash: the content-hash to check about.
        :type chash: basestring
        :return: False, if it does not exist, or UID.
        """
        exist = False
        exist = self.memstore.get_fdoc_from_chash(chash, self.mbox)

        if not exist:
            exist = self._get_fdoc_from_chash(chash)
        if exist and exist.content is not None:
            return exist.content.get(fields.UID_KEY, "unknown-uid")
        else:
            return False

    def add_msg(self, raw, subject=None, flags=None, date=None,
                notify_on_disk=False):
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

        :return: a deferred that will be fired with the message
                 uid when the adding succeed.
        :rtype: deferred
        """
        if flags is None:
            flags = tuple()
        leap_assert_type(flags, tuple)

        # TODO ---- proxy to MessageCollection addMessage

        #observer = defer.Deferred()
        #d = self._do_parse(raw)
        #d.addCallback(lambda result: reactor.callInThread(
            #self._do_add_msg, result, flags, subject, date,
            #notify_on_disk, observer))
        #return observer

    # TODO ---------------------------------------------------
    # move this to leap.mail.adaptors.soledad

    def _do_add_msg(self, parse_result, flags, subject,
                    date, notify_on_disk, observer):
        """
        """
        msg, parts, chash, size, multi = parse_result

        # XXX move to SoledadAdaptor write operation ... ???
        # check for uniqueness --------------------------------
        # Watch out! We're reserving a UID right after this!
        existing_uid = self._fdoc_already_exists(chash)
        if existing_uid:
            msg = self.get_msg_by_uid(existing_uid)
            reactor.callFromThread(observer.callback, existing_uid)
            msg.setFlags((fields.DELETED_FLAG,), -1)
            return

        # TODO move UID autoincrement to MessageCollection.addMessage(mailbox)
        # TODO S2 -- get FUCKING UID from autoincremental table
        #uid = self.memstore.increment_last_soledad_uid(self.mbox)
        #self.set_recent_flag(uid)


    # ------------------------------------------------------------

    #
    # getters: specific queries
    #

    # recent flags

    def _get_recent_flags(self):
        """
        An accessor for the recent-flags set for this mailbox.
        """
        # XXX check if we should remove this
        if self.__rflags is not None:
            return self.__rflags

        if self.memstore is not None:
            with self._rdoc_lock[self.mbox]:
                rflags = self.memstore.get_recent_flags(self.mbox)
                if not rflags:
                    # not loaded in the memory store yet.
                    # let's fetch them from soledad...
                    rdoc = self._get_recent_doc_from_soledad()
                    if rdoc is None:
                        return set([])
                    rflags = set(rdoc.content.get(
                        fields.RECENTFLAGS_KEY, []))
                    # ...and cache them now.
                    self.memstore.load_recent_flags(
                        self.mbox,
                        {'doc_id': rdoc.doc_id, 'set': rflags})
            return rflags

    def _set_recent_flags(self, value):
        """
        Setter for the recent-flags set for this mailbox.
        """
        if self.memstore is not None:
            self.memstore.set_recent_flags(self.mbox, value)

    recent_flags = property(
        _get_recent_flags, _set_recent_flags,
        doc="Set of UIDs with the recent flag for this mailbox.")

    def _get_recent_doc_from_soledad(self):
        """
        Get recent-flags document from Soledad for this mailbox.
        :rtype: SoledadDocument or None
        """
        # FIXME ----- use deferreds.
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MBOX_IDX,
            fields.TYPE_RECENT_VAL, self.mbox)
        curried.expected = "rdoc"
        with self._rdoc_read_lock[self.mbox]:
            return try_unique_query(curried)

    # Property-set modification (protected by a different
    # lock to give atomicity to the read/write operation)

    def unset_recent_flags(self, uids):
        """
        Unset Recent flag for a sequence of uids.

        :param uids: the uids to unset
        :type uid: sequence
        """
        # FIXME ----- use deferreds.
        with self._rdoc_property_lock[self.mbox]:
            self.recent_flags.difference_update(
                set(uids))

    # Individual flags operations

    def unset_recent_flag(self, uid):
        """
        Unset Recent flag for a given uid.

        :param uid: the uid to unset
        :type uid: int
        """
        # FIXME ----- use deferreds.
        with self._rdoc_property_lock[self.mbox]:
            self.recent_flags.difference_update(
                set([uid]))

    def set_recent_flag(self, uid):
        """
        Set Recent flag for a given uid.

        :param uid: the uid to set
        :type uid: int
        """
        # FIXME ----- use deferreds.
        with self._rdoc_property_lock[self.mbox]:
            self.recent_flags = self.recent_flags.union(
                set([uid]))

    # individual doc getters, message layer.

    def _get_fdoc_from_chash(self, chash):
        """
        Return a flags document for this mailbox with a given chash.

        :return: A SoledadDocument containing the Flags Document, or None if
                 the query failed.
        :rtype: SoledadDocument or None.
        """
        # USED from:
        # [ ] duplicated fdoc detection
        # [ ] _get_uid_from_msgidCb

        # FIXME ----- use deferreds.
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MBOX_C_HASH_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox, chash)
        curried.expected = "fdoc"
        fdoc = try_unique_query(curried)
        if fdoc is not None:
            return fdoc
        else:
            # probably this should be the other way round,
            # ie, try fist on memstore...
            cf = self.memstore._chash_fdoc_store
            fdoc = cf[chash][self.mbox]
            # hey, I just needed to wrap fdoc thing into
            # a "content" attribute, look a better way...
            if not empty(fdoc):
                return MessagePartDoc(
                    new=None, dirty=None, part=None,
                    store=None, doc_id=None,
                    content=fdoc)

    def _get_uid_from_msgidCb(self, msgid):
        hdoc = None
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MSGID_IDX,
            fields.TYPE_HEADERS_VAL, msgid)
        curried.expected = "hdoc"
        hdoc = try_unique_query(curried)

        # XXX this is only a quick hack to avoid regression
        # on the "multiple copies of the draft" issue, but
        # this is currently broken since  it's not efficient to
        # look for this. Should lookup better.
        # FIXME!

        if hdoc is not None:
            hdoc_dict = hdoc.content

        else:
            hdocstore = self.memstore._hdoc_store
            match = [x for _, x in hdocstore.items() if x['msgid'] == msgid]
            hdoc_dict = first(match)

        if hdoc_dict is None:
            logger.warning("Could not find hdoc for msgid %s"
                           % (msgid,))
            return None
        msg_chash = hdoc_dict.get(fields.CONTENT_HASH_KEY)

        fdoc = self._get_fdoc_from_chash(msg_chash)
        if not fdoc:
            logger.warning("Could not find fdoc for msgid %s"
                           % (msgid,))
            return None
        return fdoc.content.get(fields.UID_KEY, None)

    def _get_uid_from_msgid(self, msgid):
        """
        Return a UID for a given message-id.

        It first gets the headers-doc for that msg-id, and
        it found it queries the flags doc for the current mailbox
        for the matching content-hash.

        :return: A UID, or None
        """
        # We need to wait a little bit, cause in some of the cases
        # the query is received right after we've saved the document,
        # and we cannot find it otherwise. This seems to be enough.

        # XXX do a deferLater instead ??
        # XXX is this working?
        return self._get_uid_from_msgidCb(msgid)

    def set_flags(self, mbox, messages, flags, mode, observer):
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
            msg = getmsg(uid, mem_only=True, flags_only=True)
            if msg is not None:
                return uid, msg.setFlags(flags, mode)

        setted_flags = [set_flags(uid, flags, mode) for uid in messages]
        result = dict(filter(None, setted_flags))

        # TODO -- remove
        reactor.callFromThread(observer.callback, result)

    # getters: generic for a mailbox

    def get_msg_by_uid(self, uid, mem_only=False, flags_only=False):
        """
        Retrieves a LeapMessage by UID.
        This is used primarity in the Mailbox fetch and store methods.

        :param uid: the message uid to query by
        :type uid: int
        :param mem_only: a flag that indicates whether this Message should
                         pass a reference to soledad to retrieve missing pieces
                         or not.
        :type mem_only: bool
        :param flags_only: whether the message should carry only a reference
                           to the flags document.
        :type flags_only: bool

        :return: A LeapMessage instance matching the query,
                 or None if not found.
        :rtype: LeapMessage
        """
        msg_container = self.memstore.get_message(
            self.mbox, uid, flags_only=flags_only)

        if msg_container is not None:
            if mem_only:
                msg = IMAPMessage(None, uid, self.mbox, collection=self,
                                  container=msg_container)
            else:
                # We pass a reference to soledad just to be able to retrieve
                # missing parts that cannot be found in the container, like
                # the content docs after a copy.
                msg = IMAPMessage(self._soledad, uid, self.mbox,
                                  collection=self, container=msg_container)
        else:
            msg = IMAPMessage(self._soledad, uid, self.mbox, collection=self)

        if not msg.does_exist():
            return None
        return msg

    # FIXME --- used where ? ---------------------------------------------
    #def get_all_docs(self, _type=fields.TYPE_FLAGS_VAL):
        #"""
        #Get all documents for the selected mailbox of the
        #passed type. By default, it returns the flag docs.
#
        #If you want acess to the content, use __iter__ instead
#
        #:return: a Deferred, that will fire with a list of u1db documents
        #:rtype: Deferred (promise of list of SoledadDocument)
        #"""
        #if _type not in fields.__dict__.values():
            #raise TypeError("Wrong type passed to get_all_docs")
#
        # FIXME ----- either raise or return a deferred wrapper.
        #if sameProxiedObjects(self._soledad, None):
            #logger.warning('Tried to get messages but soledad is None!')
            #return []
#
        #def get_sorted_docs(docs):
            #all_docs = [doc for doc in docs]
            # inneficient, but first let's grok it and then
            # let's worry about efficiency.
            # XXX FIXINDEX -- should implement order by in soledad
            # FIXME ----------------------------------------------
            #return sorted(all_docs, key=lambda item: item.content['uid'])
#
        #d = self._soledad.get_from_index(
            #fields.TYPE_MBOX_IDX, _type, self.mbox)
        #d.addCallback(get_sorted_docs)
        #return d

    def all_soledad_uid_iter(self):
        """
        Return an iterator through the UIDs of all messages, sorted in
        ascending order.
        """
        # XXX FIXME ------ sorted???

        def get_uids(docs):
            return set([
                doc.content[self.UID_KEY] for doc in docs if not empty(doc)])

        d = self._soledad.get_from_index(
            fields.TYPE_MBOX_IDX, fields.TYPE_FLAGS_VAL, self.mbox)
        d.addCallback(get_uids)
        return d

    def all_uid_iter(self):
        """
        Return an iterator through the UIDs of all messages, from memory.
        """
        mem_uids = self.memstore.get_uids(self.mbox)
        soledad_known_uids = self.memstore.get_soledad_known_uids(
            self.mbox)
        combined = tuple(set(mem_uids).union(soledad_known_uids))
        return combined

    def get_all_soledad_flag_docs(self):
        """
        Return a dict with the content of all the flag documents
        in soledad store for the given mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: dict
        """
        # XXX we really could return a reduced version with
        # just {'uid': (flags-tuple,) since the prefetch is
        # only oriented to get the flag tuples.

        def get_content(docs):
            all_docs = [(
                doc.content[self.UID_KEY],
                dict(doc.content))
                for doc in docs
                if not empty(doc.content)]
            all_flags = dict(all_docs)
            return all_flags

        d = self._soledad.get_from_index(
            fields.TYPE_MBOX_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox)
        d.addCallback(get_content)
        return d

    def all_headers(self):
        """
        Return a dict with all the header documents for this
        mailbox.

        :rtype: dict
        """
        return self.memstore.all_headers(self.mbox)

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        return self.memstore.count(self.mbox)

    # unseen messages

    def unseen_iter(self):
        """
        Get an iterator for the message UIDs with no `seen` flag
        for this mailbox.

        :return: iterator through unseen message doc UIDs
        :rtype: iterable
        """
        return self.memstore.unseen_iter(self.mbox)

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
        return [IMAPMessage(self._soledad, docid, self.mbox, collection=self)
                for docid in self.unseen_iter()]

    # recent messages

    # XXX take it from memstore
    # XXX Used somewhere?
    def count_recent(self):
        """
        Count all messages with the `Recent` flag.
        It just retrieves the length of the recent_flags set,
        which is stored in a specific type of document for
        this collection.

        :returns: count
        :rtype: int
        """
        return len(self.recent_flags)

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
        return (IMAPMessage(self._soledad, docuid, self.mbox, collection=self)
                for docuid in self.all_uid_iter())

    def __repr__(self):
        """
        Representation string for this object.
        """
        return u"<MessageCollection: mbox '%s' (%s)>" % (
            self.mbox, self.count())

    # XXX should implement __eq__ also !!!
    # use chash...
