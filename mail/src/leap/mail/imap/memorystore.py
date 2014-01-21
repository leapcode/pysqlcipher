# -*- coding: utf-8 -*-
# memorystore.py
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
In-memory transient store for a LEAPIMAPServer.
"""
import contextlib
import logging
import weakref

from collections import namedtuple

from twisted.internet.task import LoopingCall
from zope.interface import implements

from leap.mail import size
from leap.mail.messageflow import MessageProducer
from leap.mail.messageparts import MessagePartType
from leap.mail.imap import interfaces
from leap.mail.imap.fields import fields

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


  XXX this is still not implemented!

"""

MessagePartDoc = namedtuple(
    'MessagePartDoc',
    ['new', 'dirty', 'part', 'store', 'content'])


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

    # XXX can use this to limit the memory footprint,
    # or is it too premature to optimize?
    # Does it work well together with the interfaces.implements?

    #__slots__ = ["_dict", "_new", "_dirty", "memstore"]

    def __init__(self, fdoc=None, hdoc=None, cdocs=None,
                 from_dict=None, memstore=None,
                 new=True, dirty=False):
        self._dict = {}

        self._new = new
        self._dirty = dirty
        self.memstore = memstore

        if from_dict is not None:
            self.from_dict(from_dict)
        else:
            if fdoc is not None:
                self._dict[self.FDOC] = ReferenciableDict(fdoc)
            if hdoc is not None:
                self._dict[self.HDOC] = ReferenciableDict(hdoc)
            if cdocs is not None:
                self._dict[self.CDOCS] = ReferenciableDict(cdocs)

    # properties

    @property
    def new(self):
        return self._new

    def set_new(self, value=True):
        self._new = value

    @property
    def dirty(self):
        return self._dirty

    def set_dirty(self, value=True):
        self._dirty = value

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
                              content=content_ref)

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
                              content=content_ref)

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
        yield self.fdoc
        yield self.hdoc
        for cdoc in self.cdocs.values():
            # XXX this will break ----
            content_ref = weakref.proxy(cdoc)
            yield MessagePartDoc(new=self.new, dirty=self.dirty,
                                 store=self._storetype,
                                 part=MessagePartType.cdoc,
                                 content=content_ref)

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
        self._dict[self.FDOC] = fdoc
        self._dict[self.HDOC] = hdoc
        self._dict[self.CDOCS] = cdocs


@contextlib.contextmanager
def set_bool_flag(obj, att):
    """
    Set a boolean flag to True while we're doing our thing.
    Just to let the world know.
    """
    setattr(obj, att, True)
    try:
        yield True
    except RuntimeError as exc:
        logger.exception(exc)
    finally:
        setattr(obj, att, False)


class MemoryStore(object):
    """
    An in-memory store to where we can write the different parts that
    we split the messages into and buffer them until we write them to the
    permanent storage.

    It uses MessageWrapper instances to represent the message-parts, which are
    indexed by mailbox name and UID.

    It also can be passed a permanent storage as a paremeter (any implementor
    of IMessageStore, in this case a SoledadStore). In this case, a periodic
    dump of the messages stored in memory will be done. The period of the
    writes to the permanent storage is controled by the write_period parameter
    in the constructor.
    """
    implements(interfaces.IMessageStore)
    implements(interfaces.IMessageStoreWriter)

    producer = None

    # TODO We will want to index by chash when we transition to local-only
    # UIDs.
    # TODO should store RECENT-FLAGS too
    # TODO should store HDOCSET too (use weakrefs!) -- will need to subclass
    # TODO do use dirty flag (maybe use namedtuples for that) so we can use it
    # also as a read-cache.

    WRITING_FLAG = "_writing"

    def __init__(self, permanent_store=None, write_period=60):
        """
        Initialize a MemoryStore.

        :param permanent_store: a IMessageStore implementor to dump
                                messages to.
        :type permanent_store: IMessageStore
        :param write_period: the interval to dump messages to disk, in seconds.
        :type write_period: int
        """
        self._permanent_store = permanent_store
        self._write_period = write_period

        # Internal Storage
        self._msg_store = {}
        self._phash_store = {}

        # TODO ----------------- implement mailbox-level flags store too! ----
        self._rflags_store = {}
        self._hdocset_store = {}
        # TODO ----------------- implement mailbox-level flags store too! ----

        # New and dirty flags, to set MessageWrapper State.
        self._new = set([])
        self._dirty = set([])

        # Flag for signaling we're busy writing to the disk storage.
        setattr(self, self.WRITING_FLAG, False)

        if self._permanent_store is not None:
            # this producer spits its messages to the permanent store
            # consumer using a queue. We will use that to put
            # our messages to be written.
            self.producer = MessageProducer(permanent_store,
                                            period=0.1)
            # looping call for dumping to SoledadStore
            self._write_loop = LoopingCall(self.write_messages,
                                           permanent_store)

            # We can start the write loop right now, why wait?
            self._start_write_loop()

    def _start_write_loop(self):
        """
        Start loop for writing to disk database.
        """
        if not self._write_loop.running:
            self._write_loop.start(self._write_period, now=True)

    def _stop_write_loop(self):
        """
        Stop loop for writing to disk database.
        """
        if self._write_loop.running:
            self._write_loop.stop()

    # IMessageStore

    # XXX this would work well for whole message operations.
    # We would have to add a put_flags operation to modify only
    # the flags doc (and set the dirty flag accordingly)

    def create_message(self, mbox, uid, message):
        """
        Create the passed message into this MemoryStore.

        By default we consider that any message is a new message.
        """
        print "adding new doc to memstore %s (%s)" % (mbox, uid)
        key = mbox, uid
        self._new.add(key)

        msg_dict = message.as_dict()
        self._msg_store[key] = msg_dict

        cdocs = message.cdocs

        dirty = key in self._dirty
        new = key in self._new

        # XXX should capture this in log...

        for cdoc_key in cdocs.keys():
            print "saving cdoc"
            cdoc = self._msg_store[key]['cdocs'][cdoc_key]

            # XXX this should be done in the MessageWrapper constructor
            # instead...
            # first we make it weak-referenciable
            referenciable_cdoc = ReferenciableDict(cdoc)
            self._msg_store[key]['cdocs'][cdoc_key] = MessagePartDoc(
                new=new, dirty=dirty, store="mem",
                part=MessagePartType.cdoc,
                content=referenciable_cdoc)
            phash = cdoc.get(fields.PAYLOAD_HASH_KEY, None)
            if not phash:
                continue
            self._phash_store[phash] = weakref.proxy(referenciable_cdoc)

    def put_message(self, mbox, uid, msg):
        """
        Put an existing message.
        """
        return NotImplementedError()

    def get_message(self, mbox, uid):
        """
        Get a MessageWrapper for the given mbox and uid combination.

        :return: MessageWrapper or None
        """
        key = mbox, uid
        msg_dict = self._msg_store.get(key, None)
        if msg_dict:
            new, dirty = self._get_new_dirty_state(key)
            return MessageWrapper(from_dict=msg_dict,
                                  memstore=weakref.proxy(self))
        else:
            return None

    def remove_message(self, mbox, uid):
        """
        Remove a Message from this MemoryStore.
        """
        raise NotImplementedError()

    # IMessageStoreWriter

    def write_messages(self, store):
        """
        Write the message documents in this MemoryStore to a different store.
        """
        # XXX pass if it's writing (ie, the queue is not empty...)
        # See how to make the writing_flag aware of the queue state...
        print "writing messages to producer..."

        with set_bool_flag(self, self.WRITING_FLAG):
            for msg_wrapper in self.all_msg_iter():
                self.producer.push(msg_wrapper)

    # MemoryStore specific methods.

    def get_uids(self, mbox):
        """
        Get all uids for a given mbox.
        """
        all_keys = self._msg_store.keys()
        return [uid for m, uid in all_keys if m == mbox]

    def get_last_uid(self, mbox):
        """
        Get the highest UID for a given mbox.
        """
        # XXX should get from msg_store keys instead!
        if not self._new:
            return 0
        return max(self.get_uids(mbox))

    def count_new_mbox(self, mbox):
        """
        Count the new messages by inbox.
        """
        return len([(m, uid) for m, uid in self._new if mbox == mbox])

    def count_new(self):
        """
        Count all the new messages in the MemoryStore.
        """
        return len(self._new)

    def get_by_phash(self, phash):
        """
        Return a content-document by its payload-hash.
        """
        doc = self._phash_store.get(phash, None)

        # XXX have to keep a mapping between phash and its linkage
        # info, to know if this payload is been already saved or not.
        # We will be able to get this from the linkage-docs,
        # not yet implemented.
        new = True
        dirty = False
        return MessagePartDoc(
            new=new, dirty=dirty, store="mem",
            part=MessagePartType.cdoc,
            content=doc)

    def all_msg_iter(self):
        """
        Return generator that iterates through all messages in the store.
        """
        return (self.get_message(*key)
                for key in sorted(self._msg_store.keys()))

    def _get_new_dirty_state(self, key):
        """
        Return `new` and `dirty` flags for a given message.
        """
        return map(lambda _set: key in _set, (self._new, self._dirty))

    @property
    def is_writing(self):
        """
        Property that returns whether the store is currently writing its
        internal state to a permanent storage.

        Used to evaluate whether the CHECK command can inform that the field
        is clear to proceed, or waiting for the write operations to complete
        is needed instead.

        :rtype: bool
        """
        # XXX this should probably return a deferred !!!
        return getattr(self, self.WRITING_FLAG)

    def put_part(self, part_type, value):
        """
        Put the passed part into this IMessageStore.
        `part` should be one of: fdoc, hdoc, cdoc
        """
        # XXX turn that into a enum

    # Memory management.

    def get_size(self):
        """
        Return the size of the internal storage.
        Use for calculating the limit beyond which we should flush the store.
        """
        return size.get_size(self._msg_store)
