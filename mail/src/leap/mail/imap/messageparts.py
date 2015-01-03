# messageparts.py
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
MessagePart implementation. Used from LeapMessage.
"""
import logging
import StringIO
import weakref

from collections import namedtuple

from enum import Enum
from zope.interface import implements
from twisted.mail import imap4

from leap.common.decorators import memoized_method
from leap.common.mail import get_email_charset
from leap.mail.imap import interfaces
from leap.mail.imap.fields import fields
from leap.mail.utils import empty, first, find_charset

MessagePartType = Enum("MessagePartType", "hdoc fdoc cdoc cdocs docs_id")


logger = logging.getLogger(__name__)


"""
A MessagePartDoc is a light wrapper around the dictionary-like
data that we pass along for message parts. It can be used almost everywhere
that you would expect a SoledadDocument, since it has a dict under the
`content` attribute.

We also keep some metadata on it, relative in part to the message as a whole,
and sometimes to a part in particular only.

* `new` indicates that the document has just been created. SoledadStore
  should just create a new doc for all the related message parts.
* `store` indicates the type of store a given MessagePartDoc lives in.
  We currently use this to indicate that  the document comes from memeory,
  but we should probably get rid of it as soon as we extend the use of the
  SoledadStore interface along LeapMessage, MessageCollection and Mailbox.
* `part` is one of the MessagePartType enums.

* `dirty` indicates that, while we already have the document in Soledad,
  we have modified its state in memory, so we need to put_doc instead while
  dumping the MemoryStore contents.
  `dirty` attribute would only apply to flags-docs and linkage-docs.
* `doc_id` is the identifier for the document in the u1db database, if any.

"""

MessagePartDoc = namedtuple(
    'MessagePartDoc',
    ['new', 'dirty', 'part', 'store', 'content', 'doc_id'])

"""
A RecentFlagsDoc is used to send the recent-flags document payload to the
SoledadWriter during dumps.
"""
RecentFlagsDoc = namedtuple(
    'RecentFlagsDoc',
    ['content', 'doc_id'])


class ReferenciableDict(dict):
    """
    A dict that can be weak-referenced.

    Some builtin objects are not weak-referenciable unless
    subclassed. So we do.

    Used to return pointers to the items in the MemoryStore.
    """


class MessageWrapper(object):
    """
    A simple nested dictionary container around the different message subparts.
    """
    implements(interfaces.IMessageContainer)

    FDOC = "fdoc"
    HDOC = "hdoc"
    CDOCS = "cdocs"
    DOCS_ID = "docs_id"

    # Using slots to limit some the memory use,
    # Add your attribute here.

    __slots__ = ["_dict", "_new", "_dirty", "_storetype", "memstore"]

    def __init__(self, fdoc=None, hdoc=None, cdocs=None,
                 from_dict=None, memstore=None,
                 new=True, dirty=False, docs_id={}):
        """
        Initialize a MessageWrapper.
        """
        # TODO add optional reference to original message in the incoming
        self._dict = {}
        self.memstore = memstore

        self._new = new
        self._dirty = dirty

        self._storetype = "mem"

        if from_dict is not None:
            self.from_dict(from_dict)
        else:
            if fdoc is not None:
                self._dict[self.FDOC] = ReferenciableDict(fdoc)
            if hdoc is not None:
                self._dict[self.HDOC] = ReferenciableDict(hdoc)
            if cdocs is not None:
                self._dict[self.CDOCS] = ReferenciableDict(cdocs)

        # This will keep references to the doc_ids to be able to put
        # messages to soledad. It will be populated during the walk() to avoid
        # the overhead of reading from the db.

        # XXX it really *only* make sense for the FDOC, the other parts
        # should not be "dirty", just new...!!!
        self._dict[self.DOCS_ID] = docs_id

    # properties

    # TODO Could refactor new and dirty properties together.

    def _get_new(self):
        """
        Get the value for the `new` flag.

        :rtype: bool
        """
        return self._new

    def _set_new(self, value=False):
        """
        Set the value for the `new` flag, and propagate it
        to the memory store if any.

        :param value: the value to set
        :type value: bool
        """
        self._new = value
        if self.memstore:
            mbox = self.fdoc.content.get('mbox', None)
            uid = self.fdoc.content.get('uid', None)
            if not mbox or not uid:
                logger.warning("Malformed fdoc")
                return
            key = mbox, uid
            fun = [self.memstore.unset_new_queued,
                   self.memstore.set_new_queued][int(value)]
            fun(key)
        else:
            logger.warning("Could not find a memstore referenced from this "
                           "MessageWrapper. The value for new will not be "
                           "propagated")

    new = property(_get_new, _set_new,
                   doc="The `new` flag for this MessageWrapper")

    def _get_dirty(self):
        """
        Get the value for the `dirty` flag.

        :rtype: bool
        """
        return self._dirty

    def _set_dirty(self, value=True):
        """
        Set the value for the `dirty` flag, and propagate it
        to the memory store if any.

        :param value: the value to set
        :type value: bool
        """
        self._dirty = value
        if self.memstore:
            mbox = self.fdoc.content.get('mbox', None)
            uid = self.fdoc.content.get('uid', None)
            if not mbox or not uid:
                logger.warning("Malformed fdoc")
                return
            key = mbox, uid
            fun = [self.memstore.unset_dirty_queued,
                   self.memstore.set_dirty_queued][int(value)]
            fun(key)
        else:
            logger.warning("Could not find a memstore referenced from this "
                           "MessageWrapper. The value for new will not be "
                           "propagated")

    dirty = property(_get_dirty, _set_dirty)

    # IMessageContainer

    @property
    def fdoc(self):
        """
        Return a MessagePartDoc wrapping around a weak reference to
        the flags-document in this MemoryStore, if any.

        :rtype: MessagePartDoc
        """
        _fdoc = self._dict.get(self.FDOC, None)
        if _fdoc:
            content_ref = weakref.proxy(_fdoc)
        else:
            logger.warning("NO FDOC!!!")
            content_ref = {}

        return MessagePartDoc(new=self.new, dirty=self.dirty,
                              store=self._storetype,
                              part=MessagePartType.fdoc,
                              content=content_ref,
                              doc_id=self._dict[self.DOCS_ID].get(
                                  self.FDOC, None))

    @property
    def hdoc(self):
        """
        Return a MessagePartDoc wrapping around a weak reference to
        the headers-document in this MemoryStore, if any.

        :rtype: MessagePartDoc
        """
        _hdoc = self._dict.get(self.HDOC, None)
        if _hdoc:
            content_ref = weakref.proxy(_hdoc)
        else:
            content_ref = {}
        return MessagePartDoc(new=self.new, dirty=self.dirty,
                              store=self._storetype,
                              part=MessagePartType.hdoc,
                              content=content_ref,
                              doc_id=self._dict[self.DOCS_ID].get(
                                  self.HDOC, None))

    @property
    def cdocs(self):
        """
        Return a weak reference to a zero-indexed dict containing
        the content-documents, or an empty dict if none found.
        If you want access to the MessagePartDoc for the individual
        parts, use the generator returned by `walk` instead.

        :rtype: dict
        """
        _cdocs = self._dict.get(self.CDOCS, None)
        if _cdocs:
            return weakref.proxy(_cdocs)
        else:
            return {}

    def walk(self):
        """
        Generator that iterates through all the parts, returning
        MessagePartDoc. Used for writing to SoledadStore.

        :rtype: generator
        """
        if self._dirty:
            try:
                mbox = self.fdoc.content[fields.MBOX_KEY]
                uid = self.fdoc.content[fields.UID_KEY]
                docid_dict = self._dict[self.DOCS_ID]
                docid_dict[self.FDOC] = self.memstore.get_docid_for_fdoc(
                    mbox, uid)
            except Exception as exc:
                logger.debug("Error while walking message...")
                logger.exception(exc)

        if not empty(self.fdoc.content) and 'uid' in self.fdoc.content:
            yield self.fdoc
        if not empty(self.hdoc.content):
            yield self.hdoc
        for cdoc in self.cdocs.values():
            if not empty(cdoc):
                content_ref = weakref.proxy(cdoc)
                yield MessagePartDoc(new=self.new, dirty=self.dirty,
                                     store=self._storetype,
                                     part=MessagePartType.cdoc,
                                     content=content_ref,
                                     doc_id=None)

    # i/o

    def as_dict(self):
        """
        Return a dict representation of the parts contained.

        :rtype: dict
        """
        return self._dict

    def from_dict(self, msg_dict):
        """
        Populate MessageWrapper parts from a dictionary.
        It expects the same format that we use in a
        MessageWrapper.


        :param msg_dict: a dictionary containing the parts to populate
                         the MessageWrapper from
        :type msg_dict: dict
        """
        fdoc, hdoc, cdocs = map(
            lambda part: msg_dict.get(part, None),
            [self.FDOC, self.HDOC, self.CDOCS])

        for t, doc in ((self.FDOC, fdoc), (self.HDOC, hdoc),
                       (self.CDOCS, cdocs)):
            self._dict[t] = ReferenciableDict(doc) if doc else None


class MessagePart(object):
    """
    IMessagePart implementor, to be passed to several methods
    of the IMAP4Server.
    It takes a subpart message and is able to find
    the inner parts.

    See the interface documentation.
    """

    implements(imap4.IMessagePart)

    def __init__(self, soledad, part_map):
        """
        Initializes the MessagePart.

        :param soledad: Soledad instance.
        :type soledad: Soledad
        :param part_map: a dictionary containing the parts map for this
                         message
        :type part_map: dict
        """
        # TODO
        # It would be good to pass the uid/mailbox also
        # for references while debugging.

        # We have a problem on bulk moves, and is
        # that when the fetch on the new mailbox is done
        # the parts maybe are not complete.
        # So we should be able to fail with empty
        # docs until we solve that. The ideal would be
        # to gather the results of the deferred operations
        # to signal the operation is complete.
        #leap_assert(part_map, "part map dict cannot be null")

        self._soledad = soledad
        self._pmap = part_map

    def getSize(self):
        """
        Return the total size, in octets, of this message part.

        :return: size of the message, in octets
        :rtype: int
        """
        if empty(self._pmap):
            return 0
        size = self._pmap.get('size', None)
        if size is None:
            logger.error("Message part cannot find size in the partmap")
            size = 0
        return size

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        fd = StringIO.StringIO()
        if not empty(self._pmap):
            multi = self._pmap.get('multi')
            if not multi:
                phash = self._pmap.get("phash", None)
            else:
                pmap = self._pmap.get('part_map')
                first_part = pmap.get('1', None)
                if not empty(first_part):
                    phash = first_part['phash']
                else:
                    phash = None

            if phash is None:
                logger.warning("Could not find phash for this subpart!")
                payload = ""
            else:
                payload = self._get_payload_from_document_memoized(phash)
                if empty(payload):
                    payload = self._get_payload_from_document(phash)

        else:
            logger.warning("Message with no part_map!")
            payload = ""

        if payload:
            content_type = self._get_ctype_from_document(phash)
            charset = find_charset(content_type)
            if charset is None:
                charset = self._get_charset(payload)
            try:
                if isinstance(payload, unicode):
                    payload = payload.encode(charset)
            except UnicodeError as exc:
                logger.error(
                    "Unicode error, using 'replace'. {0!r}".format(exc))
                payload = payload.encode(charset, 'replace')

        fd.write(payload)
        fd.seek(0)
        return fd

    # TODO should memory-bound this memoize!!!
    @memoized_method
    def _get_payload_from_document_memoized(self, phash):
        """
        Memoized method call around the regular method, to be able
        to call the non-memoized method in case we got a None.

        :param phash: the payload hash to retrieve by.
        :type phash: str or unicode
        :rtype: str or unicode or None
        """
        return self._get_payload_from_document(phash)

    def _get_payload_from_document(self, phash):
        """
        Return the message payload from the content document.

        :param phash: the payload hash to retrieve by.
        :type phash: str or unicode
        :rtype: str or unicode or None
        """
        cdocs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_CONTENT_VAL, str(phash))

        cdoc = first(cdocs)
        if cdoc is None:
            logger.warning(
                "Could not find the content doc "
                "for phash %s" % (phash,))
            payload = ""
        else:
            payload = cdoc.content.get(fields.RAW_KEY, "")
        return payload

    # TODO should memory-bound this memoize!!!
    @memoized_method
    def _get_ctype_from_document(self, phash):
        """
        Reeturn the content-type from the content document.

        :param phash: the payload hash to retrieve by.
        :type phash: str or unicode
        :rtype: str or unicode
        """
        cdocs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_CONTENT_VAL, str(phash))

        cdoc = first(cdocs)
        if not cdoc:
            logger.warning(
                "Could not find the content doc "
                "for phash %s" % (phash,))
        ctype = cdoc.content.get('ctype', "")
        return ctype

    @memoized_method
    def _get_charset(self, stuff):
        # TODO put in a common class with LeapMessage
        """
        Gets (guesses?) the charset of a payload.

        :param stuff: the stuff to guess about.
        :type stuff: str or unicode
        :return: charset
        :rtype: unicode
        """
        # XXX existential doubt 2. shouldn't we make the scope
        # of the decorator somewhat more persistent?
        # ah! yes! and put memory bounds.
        return get_email_charset(stuff)

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
        # XXX refactor together with MessagePart method
        if not self._pmap:
            logger.warning("No pmap in Subpart!")
            return {}
        headers = dict(self._pmap.get("headers", []))

        names = map(lambda s: s.upper(), names)
        if negate:
            cond = lambda key: key.upper() not in names
        else:
            cond = lambda key: key.upper() in names

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

            # filter original dict by negate-condition
            if cond(key):
                headers2[key] = value
        return headers2

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        if empty(self._pmap):
            logger.warning("Could not get part map!")
            return False
        multi = self._pmap.get("multi", False)
        return multi

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

        sub_pmap = self._pmap.get("part_map", {})
        try:
            part_map = sub_pmap[str(part + 1)]
        except KeyError:
            logger.debug("getSubpart for %s: KeyError" % (part,))
            raise IndexError

        # XXX check for validity
        return MessagePart(self._soledad, part_map)
