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
import re
import time
import threading
import StringIO

from collections import defaultdict
from functools import partial

from twisted.mail import imap4
from twisted.internet import defer
from twisted.python import log
from zope.interface import implements
from zope.proxy import sameProxiedObjects

from leap.common.check import leap_assert, leap_assert_type
from leap.common.decorators import memoized_method
from leap.common.mail import get_email_charset
from leap.mail import walk
from leap.mail.utils import first, find_charset, lowerdict, empty
from leap.mail.decorators import deferred
from leap.mail.imap.index import IndexedDB
from leap.mail.imap.fields import fields, WithMsgFields
from leap.mail.imap.memorystore import MessageWrapper
from leap.mail.imap.messageparts import MessagePart
from leap.mail.imap.parser import MailParser, MBoxParser

logger = logging.getLogger(__name__)

# TODO ------------------------------------------------------------

# [ ] Add ref to incoming message during add_msg
# [ ] Add linked-from info.
#     * Need a new type of documents: linkage info.
#     * HDOCS are linked from FDOCs (ref to chash)
#     * CDOCS are linked from HDOCS (ref to chash)

# [ ] Delete incoming mail only after successful write!
# [ ] Remove UID from syncable db. Store only those indexes locally.

CHARSET_PATTERN = r"""charset=([\w-]+)"""
MSGID_PATTERN = r"""<([\w@.]+)>"""

CHARSET_RE = re.compile(CHARSET_PATTERN, re.IGNORECASE)
MSGID_RE = re.compile(MSGID_PATTERN)


def try_unique_query(curried):
    """
    Try to execute a query that is expected to have a
    single outcome, and log a warning if more than one document found.

    :param curried: a curried function
    :type curried: callable
    """
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


class LeapMessage(fields, MailParser, MBoxParser):
    """
    The main representation of a message.

    It indexes the messages in one mailbox by a combination
    of uid+mailbox name.
    """

    # TODO this has to change.
    # Should index primarily by chash, and keep a local-lonly
    # UID table.

    implements(imap4.IMessage)

    def __init__(self, soledad, uid, mbox, collection=None, container=None):
        """
        Initializes a LeapMessage.

        :param soledad: a Soledad instance
        :type soledad: Soledad
        :param uid: the UID for the message.
        :type uid: int or basestring
        :param mbox: the mbox this message belongs to
        :type mbox: basestring
        :param collection: a reference to the parent collection object
        :type collection: MessageCollection
        :param container: a IMessageContainer implementor instance
        :type container: IMessageContainer
        """
        MailParser.__init__(self)
        self._soledad = soledad
        self._uid = int(uid)
        self._mbox = self._parse_mailbox_name(mbox)
        self._collection = collection
        self._container = container

        self.__chash = None
        self.__bdoc = None

    # XXX make these properties public

    @property
    def _fdoc(self):
        """
        An accessor to the flags document.
        """
        if all(map(bool, (self._uid, self._mbox))):
            fdoc = None
            if self._container is not None:
                fdoc = self._container.fdoc
            if not fdoc:
                fdoc = self._get_flags_doc()
            if fdoc:
                fdoc_content = fdoc.content
                self.__chash = fdoc_content.get(
                    fields.CONTENT_HASH_KEY, None)
            return fdoc

    @property
    def _hdoc(self):
        """
        An accessor to the headers document.
        """
        if self._container is not None:
            hdoc = self._container.hdoc
            if hdoc and not empty(hdoc.content):
                return hdoc
        # XXX cache this into the memory store !!!
        return self._get_headers_doc()

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
    def _bdoc(self):
        """
        An accessor to the body document.
        """
        if not self._hdoc:
            return None
        if not self.__bdoc:
            self.__bdoc = self._get_body_doc()
        return self.__bdoc

    # IMessage implementation

    def getUID(self):
        """
        Retrieve the unique identifier associated with this Message.

        :return: uid for this message
        :rtype: int
        """
        return self._uid

    def getFlags(self):
        """
        Retrieve the flags associated with this Message.

        :return: The flags, represented as strings
        :rtype: tuple
        """
        if self._uid is None:
            return []
        uid = self._uid

        flags = []
        fdoc = self._fdoc
        if fdoc:
            flags = fdoc.content.get(self.FLAGS_KEY, None)

        msgcol = self._collection

        # We treat the recent flag specially: gotten from
        # a mailbox-level document.
        if msgcol and uid in msgcol.recent_flags:
            flags.append(fields.RECENT_FLAG)
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
        # XXX use memory store ...!

        leap_assert(isinstance(flags, tuple), "flags need to be a tuple")
        log.msg('setting flags: %s (%s)' % (self._uid, flags))

        doc = self._fdoc
        if not doc:
            logger.warning(
                "Could not find FDOC for %s:%s while setting flags!" %
                (self._mbox, self._uid))
            return
        doc.content[self.FLAGS_KEY] = flags
        doc.content[self.SEEN_KEY] = self.SEEN_FLAG in flags
        doc.content[self.DEL_KEY] = self.DELETED_FLAG in flags

        if self._collection.memstore is not None:
            self._collection.memstore.put_message(
                self._mbox, self._uid,
                MessageWrapper(fdoc=doc.content, new=False, dirty=True,
                               docs_id={'fdoc': doc.doc_id}))
        else:
            # fallback for non-memstore initializations.
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
        date = self._hdoc.content.get(self.DATE_KEY, '')
        return str(date)

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
        if self._bdoc is not None:
            bdoc_content = self._bdoc.content
            if bdoc_content is None:
                logger.warning("No BODC content found for message!!!")
                return write_fd(str(""))

            body = bdoc_content.get(self.RAW_KEY, "")
            content_type = bdoc_content.get('content-type', "")
            charset = find_charset(content_type)
            logger.debug('got charset from content-type: %s' % charset)
            if charset is None:
                # XXX change for find_charset utility
                charset = self._get_charset(body)
            try:
                body = body.encode(charset)
            except UnicodeError as exc:
                logger.error("Unicode error {0}".format(exc))
                logger.debug("Attempted to encode with: %s" % charset)
                try:
                    body = body.encode(charset, 'replace')
                except UnicodeError as exc:
                    try:
                        body = body.encode('utf-8', 'replace')
                    except:
                        pass
            finally:
                return write_fd(body)

        # We are still returning funky characters from here.
        else:
            logger.warning("No BDOC found for message.")
            return write_fd(str(""))

    @memoized_method
    def _get_charset(self, stuff):
        """
        Gets (guesses?) the charset of a payload.

        :param stuff: the stuff to guess about.
        :type stuff: basestring
        :returns: charset
        """
        # TODO get from subpart headers
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
            fdoc_content = self._fdoc.content
            size = fdoc_content.get(self.SIZE_KEY, False)
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
        # TODO split in smaller methods
        headers = self._get_headers()
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

        # twisted imap server expects *some* headers to be lowercase
        # XXX refactor together with MessagePart method
        headers2 = dict()
        for key, value in headers.items():
            if key.lower() == "content-type":
                key = key.lower()

            if not isinstance(key, str):
                key = key.encode(charset, 'replace')
            if not isinstance(value, str):
                value = value.encode(charset, 'replace')

            # filter original dict by negate-condition
            if cond(key):
                headers2[key] = value

        return headers2

    def _get_headers(self):
        """
        Return the headers dict for this message.
        """
        if self._hdoc is not None:
            hdoc_content = self._hdoc.content
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
        if self._fdoc:
            fdoc_content = self._fdoc.content
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
        if not self._hdoc:
            logger.warning("Tried to get part but no HDOC found!")
            return None

        hdoc_content = self._hdoc.content
        pmap = hdoc_content.get(fields.PARTS_MAP_KEY, {})
        return pmap[str(part)]

    def _get_flags_doc(self):
        """
        Return the document that keeps the flags for this
        message.
        """
        result = {}
        try:
            flag_docs = self._soledad.get_from_index(
                fields.TYPE_MBOX_UID_IDX,
                fields.TYPE_FLAGS_VAL, self._mbox, str(self._uid))
            result = first(flag_docs)
        except Exception as exc:
            # ugh! Something's broken down there!
            logger.warning("ERROR while getting flags for UID: %s" % self._uid)
            logger.exception(exc)
        finally:
            return result

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
        hdoc_content = self._hdoc.content
        #print "hdoc: ", hdoc_content
        body_phash = hdoc_content.get(
            fields.BODY_KEY, None)
        print "body phash: ", body_phash
        if not body_phash:
            logger.warning("No body phash for this document!")
            return None

        # XXX get from memstore too...
        # if memstore: memstore.get_phrash
        # memstore should keep a dict with weakrefs to the
        # phash doc...

        if self._container is not None:
            bdoc = self._container.memstore.get_cdoc_from_phash(body_phash)
            print "bdoc from container -->", bdoc
            if bdoc and bdoc.content is not None:
                return bdoc
            else:
                print "no doc or not bdoc content for that phash found!"

        # no memstore or no doc found there
        if self._soledad:
            body_docs = self._soledad.get_from_index(
                fields.TYPE_P_HASH_IDX,
                fields.TYPE_CONTENT_VAL, str(body_phash))
            return first(body_docs)
        else:
            logger.error("No phash in container, and no soledad found!")

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
#
    #def set_uid(self, uid):
        #"""
        #Set new uid for this message.
#
        #:param uid: the new uid
        #:type uid: basestring
        #"""
        # XXX dangerous! lock?
        #self._uid = uid
        #d = self._fdoc
        #d.content[self.UID_KEY] = uid
        #self._soledad.put_doc(d)
#
    #def set_mbox(self, mbox):
        #"""
        #Set new mbox for this message.
#
        #:param mbox: the new mbox
        #:type mbox: basestring
        #"""
        # XXX dangerous! lock?
        #self._mbox = mbox
        #d = self._fdoc
        #d.content[self.MBOX_KEY] = mbox
        #self._soledad.put_doc(d)

    # destructor

    @deferred
    def remove(self):
        """
        Remove all docs associated with this message.
        Currently it removes only the flags doc.
        """
        # XXX For the moment we are only removing the flags and headers
        # docs. The rest we leave there polluting your hard disk,
        # until we think about a good way of deorphaning.
        # Maybe a crawler of unreferenced docs.

        # XXX implement elijah's idea of using a PUT document as a
        # token to ensure consistency in the removal.

        uid = self._uid

        fd = self._get_flags_doc()
        #hd = self._get_headers_doc()
        #bd = self._get_body_doc()
        #docs = [fd, hd, bd]

        try:
            memstore = self._collection.memstore
        except AttributeError:
            memstore = False

        if memstore and hasattr(fd, "store", None) == "mem":
            key = self._mbox, self._uid
            if fd.new:
                # it's a new document, so we can remove it and it will not
                # be writen. Watch out! We need to be sure it has not been
                # just queued to write!
                memstore.remove_message(*key)

            if fd.dirty:
                doc_id = fd.doc_id
                doc = self._soledad.get_doc(doc_id)
                try:
                    self._soledad.delete_doc(doc)
                except Exception as exc:
                    logger.exception(exc)

        else:
            # we just got a soledad_doc
            try:
                doc_id = fd.doc_id
                latest_doc = self._soledad.get_doc(doc_id)
                self._soledad.delete_doc(latest_doc)
            except Exception as exc:
                logger.exception(exc)
        return uid

    def does_exist(self):
        """
        Return True if there is actually a flags message for this
        UID and mbox.
        """
        return self._fdoc is not None


class MessageCollection(WithMsgFields, IndexedDB, MailParser, MBoxParser):
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
    a MUA will do in a case where we do not have local disk cache.
    """
    HDOCS_SET_DOC = "HDOCS_SET"

    templates = {

        # Message Level

        FLAGS_DOC: {
            fields.TYPE_KEY: fields.TYPE_FLAGS_VAL,
            fields.UID_KEY: 1,  # XXX moe to a local table
            fields.MBOX_KEY: fields.INBOX_VAL,
            fields.CONTENT_HASH_KEY: "",

            fields.SEEN_KEY: False,
            fields.DEL_KEY: False,
            fields.FLAGS_KEY: [],
            fields.MULTIPART_KEY: False,
            fields.SIZE_KEY: 0
        },

        HEADERS_DOC: {
            fields.TYPE_KEY: fields.TYPE_HEADERS_VAL,
            fields.CONTENT_HASH_KEY: "",

            fields.DATE_KEY: "",
            fields.SUBJECT_KEY: "",

            fields.HEADERS_KEY: {},
            fields.PARTS_MAP_KEY: {},
        },

        CONTENT_DOC: {
            fields.TYPE_KEY: fields.TYPE_CONTENT_VAL,
            fields.PAYLOAD_HASH_KEY: "",
            fields.LINKED_FROM_KEY: [],
            fields.CTYPE_KEY: "",  # should index by this too

            # should only get inmutable headers parts
            # (for indexing)
            fields.HEADERS_KEY: {},
            fields.RAW_KEY: "",
            fields.PARTS_MAP_KEY: {},
            fields.HEADERS_KEY: {},
            fields.MULTIPART_KEY: False,
        },

        # Mailbox Level

        RECENT_DOC: {
            fields.TYPE_KEY: fields.TYPE_RECENT_VAL,
            fields.MBOX_KEY: fields.INBOX_VAL,
            fields.RECENTFLAGS_KEY: [],
        },

        HDOCS_SET_DOC: {
            fields.TYPE_KEY: fields.TYPE_HDOCS_SET_VAL,
            fields.MBOX_KEY: fields.INBOX_VAL,
            fields.HDOCS_SET_KEY: [],
        }


    }

    # Different locks for wrapping both the u1db document getting/setting
    # and the property getting/settting in an atomic operation.

    # TODO we would abstract this to a SoledadProperty class

    _rdoc_lock = threading.Lock()
    _rdoc_property_lock = threading.Lock()
    _hdocset_lock = threading.Lock()
    _hdocset_property_lock = threading.Lock()

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
        MailParser.__init__(self)
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
        self.__hdocset = None
        self.initialize_db()

        # ensure that we have a recent-flags and a hdocs-sec doc
        self._get_or_create_rdoc()
        self._get_or_create_hdocset()

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

    def _get_or_create_rdoc(self):
        """
        Try to retrieve the recent-flags doc for this MessageCollection,
        and create one if not found.
        """
        rdoc = self._get_recent_doc()
        if not rdoc:
            rdoc = self._get_empty_doc(self.RECENT_DOC)
            if self.mbox != fields.INBOX_VAL:
                rdoc[fields.MBOX_KEY] = self.mbox
            self._soledad.create_doc(rdoc)

    def _get_or_create_hdocset(self):
        """
        Try to retrieve the hdocs-set doc for this MessageCollection,
        and create one if not found.
        """
        hdocset = self._get_hdocset_doc()
        if not hdocset:
            hdocset = self._get_empty_doc(self.HDOCS_SET_DOC)
            if self.mbox != fields.INBOX_VAL:
                hdocset[fields.MBOX_KEY] = self.mbox
            self._soledad.create_doc(hdocset)

    def _do_parse(self, raw):
        """
        Parse raw message and return it along with
        relevant information about its outer level.

        :param raw: the raw message
        :type raw: StringIO or basestring
        :return: msg, chash, size, multi
        :rtype: tuple
        """
        msg = self._get_parsed_msg(raw)
        chash = self._get_hash(msg)
        size = len(msg.as_string())
        multi = msg.is_multipart()
        return msg, chash, size, multi

    def _populate_flags(self, flags, uid, chash, size, multi):
        """
        Return a flags doc.

        XXX Missing DOC -----------
        """
        fd = self._get_empty_doc(self.FLAGS_DOC)

        fd[self.MBOX_KEY] = self.mbox
        fd[self.UID_KEY] = uid
        fd[self.CONTENT_HASH_KEY] = chash
        fd[self.SIZE_KEY] = size
        fd[self.MULTIPART_KEY] = multi
        if flags:
            fd[self.FLAGS_KEY] = map(self._stringify, flags)
            fd[self.SEEN_KEY] = self.SEEN_FLAG in flags
            fd[self.DEL_KEY] = self.DELETED_FLAG in flags
            fd[self.RECENT_KEY] = True  # set always by default
        return fd

    def _populate_headr(self, msg, chash, subject, date):
        """
        Return a headers doc.

        XXX Missing DOC -----------
        """
        headers = defaultdict(list)
        for k, v in msg.items():
            headers[k].append(v)

        # "fix" for repeated headers.
        for k, v in headers.items():
            newline = "\n%s: " % (k,)
            headers[k] = newline.join(v)

        lower_headers = lowerdict(headers)
        msgid = first(MSGID_RE.findall(
            lower_headers.get('message-id', '')))

        hd = self._get_empty_doc(self.HEADERS_DOC)
        hd[self.CONTENT_HASH_KEY] = chash
        hd[self.HEADERS_KEY] = headers
        hd[self.MSGID_KEY] = msgid

        if not subject and self.SUBJECT_FIELD in headers:
            hd[self.SUBJECT_KEY] = headers[self.SUBJECT_FIELD]
        else:
            hd[self.SUBJECT_KEY] = subject

        if not date and self.DATE_FIELD in headers:
            hd[self.DATE_KEY] = headers[self.DATE_FIELD]
        else:
            hd[self.DATE_KEY] = date
        return hd

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
        if self.memstore is not None:
            exist = self.memstore.get_fdoc_from_chash(chash, self.mbox)

        if not exist:
            exist = self._get_fdoc_from_chash(chash)

        print "FDOC EXIST?", exist
        if exist:
            return exist.content.get(fields.UID_KEY, "unknown-uid")
        else:
            return False

    # not deferring to thread cause this now uses deferred asa retval
    #@deferred
    def add_msg(self, raw, subject=None, flags=None, date=None, uid=1):
        """
        Creates a new message document.
        Here lives the magic of the leap mail. Well, in soledad, really.

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
        # TODO signal that we can delete the original message!-----
        # when all the processing is done.

        # TODO add the linked-from info !
        # TODO add reference to the original message
        print "ADDING MESSAGE..."

        logger.debug('adding message')
        if flags is None:
            flags = tuple()
        leap_assert_type(flags, tuple)

        # parse
        msg, chash, size, multi = self._do_parse(raw)

        # check for uniqueness.
        if self._fdoc_already_exists(chash):
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            print
            print
            logger.warning("We already have that message in this mailbox.")
            # note that this operation will leave holes in the UID sequence,
            # but we're gonna change that all the same for a local-only table.
            # so not touch it by the moment.
            return defer.succeed('already_exists')

        fd = self._populate_flags(flags, uid, chash, size, multi)
        hd = self._populate_headr(msg, chash, subject, date)

        parts = walk.get_parts(msg)
        body_phash_fun = [walk.get_body_phash_simple,
                          walk.get_body_phash_multi][int(multi)]
        body_phash = body_phash_fun(walk.get_payloads(msg))
        parts_map = walk.walk_msg_tree(parts, body_phash=body_phash)

        # add parts map to header doc
        # (body, multi, part_map)
        for key in parts_map:
            hd[key] = parts_map[key]
        del parts_map

        # The MessageContainer expects a dict, zero-indexed
        # XXX review-me
        cdocs = dict((index, doc) for index, doc in
                     enumerate(walk.get_raw_docs(msg, parts)))
        print "cdocs is", cdocs

        # Saving ----------------------------------------
        # XXX should check for content duplication on headers too
        # but with chash. !!!

        # XXX adapt hdocset to use memstore
        #hdoc = self._soledad.create_doc(hd)
        # We add the newly created hdoc to the fast-access set of
        # headers documents associated with the mailbox.
        #self.add_hdocset_docid(hdoc.doc_id)

        # XXX move to memory store too
        # self.set_recent_flag(uid)

        # TODO ---- add reference to original doc, to be deleted
        # after writes are done.
        msg_container = MessageWrapper(fd, hd, cdocs)

        # XXX Should allow also to dump to disk directly,
        # for no-memstore cases.

        # we return a deferred that, by default, will be triggered when
        # saved to disk
        d = self.memstore.create_message(self.mbox, uid, msg_container)
        print "defered-add", d
        print "adding message", d
        return d

    def _remove_cb(self, result):
        return result

    def remove_all_deleted(self):
        """
        Removes all messages flagged as deleted.
        """
        delete_deferl = []
        for msg in self.get_deleted():
            delete_deferl.append(msg.remove())
        d1 = defer.gatherResults(delete_deferl, consumeErrors=True)
        d1.addCallback(self._remove_cb)
        return d1

    def remove(self, msg):
        """
        Remove a given msg.
        :param msg: the message to be removed
        :type msg: LeapMessage
        """
        d = msg.remove()
        d.addCallback(self._remove_cb)
        return d

    #
    # getters: specific queries
    #

    # recent flags
    # XXX FIXME -------------------------------------
    # This should be rewritten to use memory store.

    def _get_recent_flags(self):
        """
        An accessor for the recent-flags set for this mailbox.
        """
        if not self.__rflags:
            with self._rdoc_lock:
                rdoc = self._get_recent_doc()
                self.__rflags = set(rdoc.content.get(
                    fields.RECENTFLAGS_KEY, []))
        return self.__rflags

    def _set_recent_flags(self, value):
        """
        Setter for the recent-flags set for this mailbox.
        """
        with self._rdoc_lock:
            rdoc = self._get_recent_doc()
            newv = set(value)
            self.__rflags = newv
            rdoc.content[fields.RECENTFLAGS_KEY] = list(newv)
            # XXX should deferLater 0 it?
            self._soledad.put_doc(rdoc)

    recent_flags = property(
        _get_recent_flags, _set_recent_flags,
        doc="Set of UIDs with the recent flag for this mailbox.")

    def _get_recent_doc(self):
        """
        Get recent-flags document for this mailbox.
        """
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MBOX_IDX,
            fields.TYPE_RECENT_VAL, self.mbox)
        curried.expected = "rdoc"
        rdoc = try_unique_query(curried)
        return rdoc

    # Property-set modification (protected by a different
    # lock to give atomicity to the read/write operation)

    def unset_recent_flags(self, uids):
        """
        Unset Recent flag for a sequence of uids.
        """
        with self._rdoc_property_lock:
            self.recent_flags = self.recent_flags.difference(
                set(uids))

    def unset_recent_flag(self, uid):
        """
        Unset Recent flag for a given uid.
        """
        with self._rdoc_property_lock:
            self.recent_flags = self.recent_flags.difference(
                set([uid]))

    def set_recent_flag(self, uid):
        """
        Set Recent flag for a given uid.
        """
        with self._rdoc_property_lock:
            self.recent_flags = self.recent_flags.union(
                set([uid]))

    # headers-docs-set

    # XXX FIXME -------------------------------------
    # This should be rewritten to use memory store.

    def _get_hdocset(self):
        """
        An accessor for the hdocs-set for this mailbox.
        """
        if not self.__hdocset:
            with self._hdocset_lock:
                hdocset_doc = self._get_hdocset_doc()
                value = set(hdocset_doc.content.get(
                    fields.HDOCS_SET_KEY, []))
                self.__hdocset = value
        return self.__hdocset

    def _set_hdocset(self, value):
        """
        Setter for the hdocs-set for this mailbox.
        """
        with self._hdocset_lock:
            hdocset_doc = self._get_hdocset_doc()
            newv = set(value)
            self.__hdocset = newv
            hdocset_doc.content[fields.HDOCS_SET_KEY] = list(newv)
            # XXX should deferLater 0 it?
            self._soledad.put_doc(hdocset_doc)

    _hdocset = property(
        _get_hdocset, _set_hdocset,
        doc="Set of Document-IDs for the headers docs associated "
            "with this mailbox.")

    def _get_hdocset_doc(self):
        """
        Get hdocs-set document for this mailbox.
        """
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MBOX_IDX,
            fields.TYPE_HDOCS_SET_VAL, self.mbox)
        curried.expected = "hdocset"
        hdocset_doc = try_unique_query(curried)
        return hdocset_doc

    # Property-set modification (protected by a different
    # lock to give atomicity to the read/write operation)

    def remove_hdocset_docids(self, docids):
        """
        Remove the given document IDs from the set of
        header-documents associated with this mailbox.
        """
        with self._hdocset_property_lock:
            self._hdocset = self._hdocset.difference(
                set(docids))

    def remove_hdocset_docid(self, docid):
        """
        Remove the given document ID from the set of
        header-documents associated with this mailbox.
        """
        with self._hdocset_property_lock:
            self._hdocset = self._hdocset.difference(
                set([docid]))

    def add_hdocset_docid(self, docid):
        """
        Add the given document ID to the set of
        header-documents associated with this mailbox.
        """
        with self._hdocset_property_lock:
            self._hdocset = self._hdocset.union(
                set([docid]))

    # individual doc getters, message layer.

    def _get_fdoc_from_chash(self, chash):
        """
        Return a flags document for this mailbox with a given chash.

        :return: A SoledadDocument containing the Flags Document, or None if
                 the query failed.
        :rtype: SoledadDocument or None.
        """
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MBOX_C_HASH_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox, chash)
        curried.expected = "fdoc"
        return try_unique_query(curried)

    def _get_uid_from_msgidCb(self, msgid):
        hdoc = None
        curried = partial(
            self._soledad.get_from_index,
            fields.TYPE_MSGID_IDX,
            fields.TYPE_HEADERS_VAL, msgid)
        curried.expected = "hdoc"
        hdoc = try_unique_query(curried)

        if hdoc is None:
            logger.warning("Could not find hdoc for msgid %s"
                           % (msgid,))
            return None
        msg_chash = hdoc.content.get(fields.CONTENT_HASH_KEY)
        fdoc = self._get_fdoc_from_chash(msg_chash)
        if not fdoc:
            logger.warning("Could not find fdoc for msgid %s"
                           % (msgid,))
            return None
        return fdoc.content.get(fields.UID_KEY, None)

    @deferred
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
        # FIXME this won't be needed after the CHECK command is implemented.
        time.sleep(0.3)
        return self._get_uid_from_msgidCb(msgid)

    # getters: generic for a mailbox

    def get_msg_by_uid(self, uid):
        """
        Retrieves a LeapMessage by UID.
        This is used primarity in the Mailbox fetch and store methods.

        :param uid: the message uid to query by
        :type uid: int

        :return: A LeapMessage instance matching the query,
                 or None if not found.
        :rtype: LeapMessage
        """
        msg_container = self.memstore.get_message(self.mbox, uid)
        if msg_container is not None:
            # We pass a reference to soledad just to be able to retrieve
            # missing parts that cannot be found in the container, like
            # the content docs after a copy.
            msg = LeapMessage(self._soledad, uid, self.mbox, collection=self,
                              container=msg_container)
        else:
            msg = LeapMessage(self._soledad, uid, self.mbox, collection=self)
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
        # FIXME ----------------------------------------------
        return sorted(all_docs, key=lambda item: item.content['uid'])

    def all_uid_iter(self):
        """
        Return an iterator trhough the UIDs of all messages, sorted in
        ascending order.
        """
        # XXX we should get this from the uid table, local-only
        # XXX FIXME -------------
        # This should be cached in the memstoretoo
        db_uids = set([doc.content[self.UID_KEY] for doc in
                       self._soledad.get_from_index(
                           fields.TYPE_MBOX_IDX,
                           fields.TYPE_FLAGS_VAL, self.mbox)])
        if self.memstore is not None:
            mem_uids = self.memstore.get_uids(self.mbox)
            uids = db_uids.union(set(mem_uids))
        else:
            uids = db_uids

        return (u for u in sorted(uids))

    def reset_last_uid(self, param):
        """
        Set the last uid to the highest uid found.
        Used while expunging, passed as a callback.
        """
        try:
            self.last_uid = max(self.all_uid_iter()) + 1
        except ValueError:
            # empty sequence
            pass
        return param

    def all_flags(self):
        """
        Return a dict with all flags documents for this mailbox.
        """
        # XXX get all from memstore and cache it there
        # FIXME should get all uids, get them fro memstore,
        # and get only the missing ones from disk.

        all_flags = dict(((
            doc.content[self.UID_KEY],
            doc.content[self.FLAGS_KEY]) for doc in
            self._soledad.get_from_index(
                fields.TYPE_MBOX_IDX,
                fields.TYPE_FLAGS_VAL, self.mbox)))
        if self.memstore is not None:
            # XXX
            uids = self.memstore.get_uids(self.mbox)
            docs = ((uid, self.memstore.get_message(self.mbox, uid))
                    for uid in uids)
            for uid, doc in docs:
                all_flags[uid] = doc.fdoc.content[self.FLAGS_KEY]

        return all_flags

    def all_flags_chash(self):
        """
        Return a dict with the content-hash for all flag documents
        for this mailbox.
        """
        all_flags_chash = dict(((
            doc.content[self.UID_KEY],
            doc.content[self.CONTENT_HASH_KEY]) for doc in
            self._soledad.get_from_index(
                fields.TYPE_MBOX_IDX,
                fields.TYPE_FLAGS_VAL, self.mbox)))
        return all_flags_chash

    def all_headers(self):
        """
        Return a dict with all the headers documents for this
        mailbox.
        """
        all_headers = dict(((
            doc.content[self.CONTENT_HASH_KEY],
            doc.content[self.HEADERS_KEY]) for doc in
            self._soledad.get_docs(self._hdocset)))
        return all_headers

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        # XXX We could cache this in memstore too until next write...
        count = self._soledad.get_count_from_index(
            fields.TYPE_MBOX_IDX,
            fields.TYPE_FLAGS_VAL, self.mbox)
        if self.memstore is not None:
            count += self.memstore.count_new()
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

    # deleted messages

    def deleted_iter(self):
        """
        Get an iterator for the message UIDs with `deleted` flag.

        :return: iterator through deleted message docs
        :rtype: iterable
        """
        return (doc.content[self.UID_KEY] for doc in
                self._soledad.get_from_index(
                    fields.TYPE_MBOX_DEL_IDX,
                    fields.TYPE_FLAGS_VAL, self.mbox, '1'))

    def get_deleted(self):
        """
        Get all messages with the `Deleted` flag.

        :returns: a generator of LeapMessages
        :rtype: generator
        """
        return (LeapMessage(self._soledad, docid, self.mbox)
                for docid in self.deleted_iter())

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
                for docuid in self.all_uid_iter())

    def __repr__(self):
        """
        Representation string for this object.
        """
        return u"<MessageCollection: mbox '%s' (%s)>" % (
            self.mbox, self.count())

    # XXX should implement __eq__ also !!!
    # use chash...
