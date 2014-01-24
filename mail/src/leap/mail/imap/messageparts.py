# -*- coding: utf-8 -*-
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
import re
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
from leap.mail.utils import first

MessagePartType = Enum("hdoc", "fdoc", "cdoc")


logger = logging.getLogger(__name__)


# XXX not needed anymoar ...
CHARSET_PATTERN = r"""charset=([\w-]+)"""
CHARSET_RE = re.compile(CHARSET_PATTERN, re.IGNORECASE)

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

    # XXX can use this to limit the memory footprint,
    # or is it too premature to optimize?
    # Does it work well together with the interfaces.implements?

    #__slots__ = ["_dict", "_new", "_dirty", "memstore"]

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
        self._dict[self.DOCS_ID] = docs_id

    # properties

    def _get_new(self):
        """
        Get the value for the `new` flag.
        """
        return self._new

    def _set_new(self, value=True):
        """
        Set the value for the `new` flag, and propagate it
        to the memory store if any.
        """
        self._new = value
        if self.memstore:
            mbox = self.fdoc.content['mbox']
            uid = self.fdoc.content['uid']
            key = mbox, uid
            fun = [self.memstore.unset_new,
                   self.memstore.set_new][int(value)]
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
        """
        return self._dirty

    def _set_dirty(self, value=True):
        """
        Set the value for the `dirty` flag, and propagate it
        to the memory store if any.
        """
        self._dirty = value
        if self.memstore:
            mbox = self.fdoc.content['mbox']
            uid = self.fdoc.content['uid']
            key = mbox, uid
            fun = [self.memstore.unset_dirty,
                   self.memstore.set_dirty][int(value)]
            fun(key)
        else:
            logger.warning("Could not find a memstore referenced from this "
                           "MessageWrapper. The value for new will not be "
                           "propagated")

    dirty = property(_get_dirty, _set_dirty)

    # IMessageContainer

    @property
    def fdoc(self):
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
        _hdoc = self._dict.get(self.HDOC, None)
        if _hdoc:
            content_ref = weakref.proxy(_hdoc)
        else:
            logger.warning("NO HDOC!!!!")
            content_ref = {}
        return MessagePartDoc(new=self.new, dirty=self.dirty,
                              store=self._storetype,
                              part=MessagePartType.hdoc,
                              content=content_ref,
                              doc_id=self._dict[self.DOCS_ID].get(
                                  self.HDOC, None))

    @property
    def cdocs(self):
        _cdocs = self._dict.get(self.CDOCS, None)
        if _cdocs:
            return weakref.proxy(_cdocs)
        else:
            return {}

    def walk(self):
        """
        Generator that iterates through all the parts, returning
        MessagePartDoc.
        """
        if self.fdoc is not None:
            yield self.fdoc
        if self.hdoc is not None:
            yield self.hdoc
        for cdoc in self.cdocs.values():
            if cdoc is not None:
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
        """
        return self._dict

    def from_dict(self, msg_dict):
        """
        Populate MessageWrapper parts from a dictionary.
        It expects the same format that we use in a
        MessageWrapper.
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

    Excusatio non petita: see the interface documentation.
    """

    implements(imap4.IMessagePart)

    def __init__(self, soledad, part_map):
        """
        Initializes the MessagePart.

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
        if not self._pmap:
            return 0
        size = self._pmap.get('size', None)
        if not size:
            logger.error("Message part cannot find size in the partmap")
        return size

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        fd = StringIO.StringIO()
        if self._pmap:
            multi = self._pmap.get('multi')
            if not multi:
                phash = self._pmap.get("phash", None)
            else:
                pmap = self._pmap.get('part_map')
                first_part = pmap.get('1', None)
                if first_part:
                    phash = first_part['phash']

            if not phash:
                logger.warning("Could not find phash for this subpart!")
                payload = str("")
            else:
                payload = self._get_payload_from_document(phash)

        else:
            logger.warning("Message with no part_map!")
            payload = str("")

        if payload:
            # XXX use find_charset instead --------------------------
            # bad rebase???
            content_type = self._get_ctype_from_document(phash)
            charset = first(CHARSET_RE.findall(content_type))
            logger.debug("Got charset from header: %s" % (charset,))
            if not charset:
                charset = self._get_charset(payload)
            try:
                payload = payload.encode(charset)
            except UnicodeError as exc:
                logger.error("Unicode error {0}".format(exc))
                payload = payload.encode(charset, 'replace')

        fd.write(payload)
        fd.seek(0)
        return fd

    # TODO cache the phash retrieval
    def _get_payload_from_document(self, phash):
        """
        Gets the message payload from the content document.

        :param phash: the payload hash to retrieve by.
        :type phash: basestring
        """
        cdocs = self._soledad.get_from_index(
            fields.TYPE_P_HASH_IDX,
            fields.TYPE_CONTENT_VAL, str(phash))

        cdoc = first(cdocs)
        if not cdoc:
            logger.warning(
                "Could not find the content doc "
                "for phash %s" % (phash,))
        payload = cdoc.content.get(fields.RAW_KEY, "")
        return payload

    # TODO cache the pahash retrieval
    def _get_ctype_from_document(self, phash):
        """
        Gets the content-type from the content document.

        :param phash: the payload hash to retrieve by.
        :type phash: basestring
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
        :type stuff: basestring
        :returns: charset
        """
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
        if not self._pmap:
            logger.warning("No pmap in Subpart!")
            return {}
        headers = dict(self._pmap.get("headers", []))

        # twisted imap server expects *some* headers to be lowercase
        # We could use a CaseInsensitiveDict here...
        headers = dict(
            (str(key), str(value)) if key.lower() != "content-type"
            else (str(key.lower()), str(value))
            for (key, value) in headers.items())

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
        filtered = dict(filter_by_cond)
        return filtered

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        if not self._pmap:
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
