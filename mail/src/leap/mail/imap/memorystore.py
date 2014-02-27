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
import threading
import weakref

from collections import defaultdict
from copy import copy

from enum import Enum
from twisted.internet import defer
from twisted.internet.task import LoopingCall
from twisted.python import log
from zope.interface import implements

from leap.common.check import leap_assert_type
from leap.mail import size
from leap.mail.utils import empty, phash_iter
from leap.mail.messageflow import MessageProducer
from leap.mail.imap import interfaces
from leap.mail.imap.fields import fields
from leap.mail.imap.messageparts import MessagePartType, MessagePartDoc
from leap.mail.imap.messageparts import RecentFlagsDoc
from leap.mail.imap.messageparts import MessageWrapper
from leap.mail.imap.messageparts import ReferenciableDict

from leap.mail.decorators import deferred_to_thread

logger = logging.getLogger(__name__)


# The default period to do writebacks to the permanent
# soledad storage, in seconds.
SOLEDAD_WRITE_PERIOD = 15

FDOC = MessagePartType.fdoc.key
HDOC = MessagePartType.hdoc.key
CDOCS = MessagePartType.cdocs.key
DOCS_ID = MessagePartType.docs_id.key


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


DirtyState = Enum("none", "dirty", "new")


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
    implements(interfaces.IMessageStore,
               interfaces.IMessageStoreWriter)

    # TODO We will want to index by chash when we transition to local-only
    # UIDs.

    WRITING_FLAG = "_writing"
    _last_uid_lock = threading.Lock()
    _fdoc_docid_lock = threading.Lock()

    def __init__(self, permanent_store=None,
                 write_period=SOLEDAD_WRITE_PERIOD):
        """
        Initialize a MemoryStore.

        :param permanent_store: a IMessageStore implementor to dump
                                messages to.
        :type permanent_store: IMessageStore
        :param write_period: the interval to dump messages to disk, in seconds.
        :type write_period: int
        """
        from twisted.internet import reactor
        self.reactor = reactor

        self._permanent_store = permanent_store
        self._write_period = write_period

        # Internal Storage: messages
        """
        flags document store.
        _fdoc_store[mbox][uid] = { 'content': 'aaa' }
        """
        self._fdoc_store = defaultdict(lambda: defaultdict(
            lambda: ReferenciableDict({})))

        # Sizes
        """
        {'mbox, uid': <int>}
        """
        self._sizes = {}

        # Internal Storage: payload-hash
        """
        fdocs:doc-id store, stores document IDs for putting
        the dirty flags-docs.
        """
        self._fdoc_id_store = defaultdict(lambda: defaultdict(
            lambda: ''))

        # Internal Storage: content-hash:hdoc
        """
        hdoc-store keeps references to
        the header-documents indexed by content-hash.

        {'chash': { dict-stuff }
        }
        """
        self._hdoc_store = defaultdict(lambda: ReferenciableDict({}))

        # Internal Storage: payload-hash:cdoc
        """
        content-docs stored by payload-hash
        {'phash': { dict-stuff } }
        """
        self._cdoc_store = defaultdict(lambda: ReferenciableDict({}))

        # Internal Storage: content-hash:fdoc
        """
        chash-fdoc-store keeps references to
        the flag-documents indexed by content-hash.

        {'chash': {'mbox-a': weakref.proxy(dict),
                   'mbox-b': weakref.proxy(dict)}
        }
        """
        self._chash_fdoc_store = defaultdict(lambda: defaultdict(lambda: None))

        # Internal Storage: recent-flags store
        """
        recent-flags store keeps one dict per mailbox,
        with the document-id of the u1db document
        and the set of the UIDs that have the recent flag.

        {'mbox-a': {'doc_id': 'deadbeef',
                    'set': {1,2,3,4}
                    }
        }
        """
        # TODO this will have to transition to content-hash
        # indexes after we move to local-only UIDs.

        self._rflags_store = defaultdict(
            lambda: {'doc_id': None, 'set': set([])})

        """
        last-uid store keeps the count of the highest UID
        per mailbox.

        {'mbox-a': 42,
         'mbox-b': 23}
        """
        self._last_uid = defaultdict(lambda: 0)

        """
        known-uids keeps a count of the uids that soledad knows for a given
        mailbox

        {'mbox-a': set([1,2,3])}
        """
        self._known_uids = defaultdict(set)

        # New and dirty flags, to set MessageWrapper State.
        self._new = set([])
        self._new_queue = set([])
        self._new_deferreds = {}

        self._dirty = set([])
        self._dirty_queue = set([])
        self._dirty_deferreds = {}

        self._rflags_dirty = set([])

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
        else:
            # We have a memory-only store.
            self.producer = None
            self._write_loop = None

    def _start_write_loop(self):
        """
        Start loop for writing to disk database.
        """
        if self._write_loop is None:
            return
        if not self._write_loop.running:
            self._write_loop.start(self._write_period, now=True)

    def _stop_write_loop(self):
        """
        Stop loop for writing to disk database.
        """
        if self._write_loop is None:
            return
        if self._write_loop.running:
            self._write_loop.stop()

    # IMessageStore

    # XXX this would work well for whole message operations.
    # We would have to add a put_flags operation to modify only
    # the flags doc (and set the dirty flag accordingly)

    def create_message(self, mbox, uid, message, observer,
                       notify_on_disk=True):
        """
        Create the passed message into this MemoryStore.

        By default we consider that any message is a new message.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the UID for the message
        :type uid: int
        :param message: a message to be added
        :type message: MessageWrapper
        :param observer: the deferred that will fire with the
                         UID of the message. If notify_on_disk is True,
                         this will happen when the message is written to
                         Soledad. Otherwise it will fire as soon as we've
                         added the message to the memory store.
        :type observer: Deferred
        :param notify_on_disk: whether the `observer` deferred should
                               wait until the message is written to disk to
                               be fired.
        :type notify_on_disk: bool
        """
        log.msg("Adding new doc to memstore %r (%r)" % (mbox, uid))
        key = mbox, uid

        self._add_message(mbox, uid, message, notify_on_disk)
        self._new.add(key)

        if observer is not None:
            if notify_on_disk:
                # We store this deferred so we can keep track of the pending
                # operations internally.
                # TODO this should fire with the UID !!! -- change that in
                # the soledad store code.
                self._new_deferreds[key] = observer

            else:
                # Caller does not care, just fired and forgot, so we pass
                # a defer that will inmediately have its callback triggered.
                self.reactor.callFromThread(observer.callback, uid)

    def put_message(self, mbox, uid, message, notify_on_disk=True):
        """
        Put an existing message.

        This will also set the dirty flag on the MemoryStore.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the UID for the message
        :type uid: int
        :param message: a message to be added
        :type message: MessageWrapper
        :param notify_on_disk: whether the deferred that is returned should
                               wait until the message is written to disk to
                               be fired.
        :type notify_on_disk: bool

        :return: a Deferred. if notify_on_disk is True, will be fired
                 when written to the db on disk.
                 Otherwise will fire inmediately
        :rtype: Deferred
        """
        key = mbox, uid
        d = defer.Deferred()
        d.addCallback(lambda result: log.msg("message PUT save: %s" % result))

        self._dirty.add(key)
        self._dirty_deferreds[key] = d
        self._add_message(mbox, uid, message, notify_on_disk)
        return d

    def _add_message(self, mbox, uid, message, notify_on_disk=True):
        """
        Helper method, called by both create_message and put_message.
        See those for parameter documentation.
        """
        msg_dict = message.as_dict()

        fdoc = msg_dict.get(FDOC, None)
        if fdoc is not None:
            fdoc_store = self._fdoc_store[mbox][uid]
            fdoc_store.update(fdoc)
            chash_fdoc_store = self._chash_fdoc_store

            # content-hash indexing
            chash = fdoc.get(fields.CONTENT_HASH_KEY)
            chash_fdoc_store[chash][mbox] = weakref.proxy(
                self._fdoc_store[mbox][uid])

        hdoc = msg_dict.get(HDOC, None)
        if hdoc is not None:
            chash = hdoc.get(fields.CONTENT_HASH_KEY)
            hdoc_store = self._hdoc_store[chash]
            hdoc_store.update(hdoc)

        cdocs = message.cdocs
        for cdoc in cdocs.values():
            phash = cdoc.get(fields.PAYLOAD_HASH_KEY, None)
            if not phash:
                continue
            cdoc_store = self._cdoc_store[phash]
            cdoc_store.update(cdoc)

        # Update memory store size
        # XXX this should use [mbox][uid]
        # TODO --- this has to be deferred to thread,
        # TODO add hdoc and cdocs sizes too
        # it's slowing things down here.
        #key = mbox, uid
        #self._sizes[key] = size.get_size(self._fdoc_store[key])

    def purge_fdoc_store(self, mbox):
        """
        Purge the empty documents from a fdoc store.
        Called during initialization of the SoledadMailbox

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        # XXX This is really a workaround until I find the conditions
        # that are making the empty items remain there.
        # This happens, for instance, after running several times
        # the regression test, that issues a store deleted + expunge + select
        # The items are being correclty deleted, but in succesive appends
        # the empty items with previously deleted uids reappear as empty
        # documents. I suspect it's a timing condition with a previously
        # evaluated sequence being used after the items has been removed.

        for uid, value in self._fdoc_store[mbox].items():
            if empty(value):
                del self._fdoc_store[mbox][uid]

    def get_docid_for_fdoc(self, mbox, uid):
        """
        Return Soledad document id for the flags-doc for a given mbox and uid,
        or None of no flags document could be found.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the message UID
        :type uid: int
        :rtype: unicode or None
        """
        with self._fdoc_docid_lock:
            doc_id = self._fdoc_id_store[mbox][uid]

        if empty(doc_id):
            fdoc = self._permanent_store.get_flags_doc(mbox, uid)
            if empty(fdoc) or empty(fdoc.content):
                return None
            doc_id = fdoc.doc_id
            self._fdoc_id_store[mbox][uid] = doc_id

        return doc_id

    def get_message(self, mbox, uid, dirtystate=DirtyState.none,
                    flags_only=False):
        """
        Get a MessageWrapper for the given mbox and uid combination.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the message UID
        :type uid: int
        :param dirtystate: DirtyState enum: one of `dirty`, `new`
                           or `none` (default)
        :type dirtystate: enum
        :param flags_only: whether the message should carry only a reference
                           to the flags document.
        :type flags_only: bool
        :

        :return: MessageWrapper or None
        """
        if dirtystate == DirtyState.dirty:
            flags_only = True

        key = mbox, uid

        fdoc = self._fdoc_store[mbox][uid]
        if empty(fdoc):
            return None

        new, dirty = False, False
        if dirtystate == DirtyState.none:
            new, dirty = self._get_new_dirty_state(key)
        if dirtystate == DirtyState.dirty:
            new, dirty = False, True
        if dirtystate == DirtyState.new:
            new, dirty = True, False

        if flags_only:
            return MessageWrapper(fdoc=fdoc,
                                  new=new, dirty=dirty,
                                  memstore=weakref.proxy(self))
        else:
            chash = fdoc.get(fields.CONTENT_HASH_KEY)
            hdoc = self._hdoc_store[chash]
            if empty(hdoc):
                hdoc = self._permanent_store.get_headers_doc(chash)
                if empty(hdoc):
                    return None
                if not empty(hdoc.content):
                    self._hdoc_store[chash] = hdoc.content
                    hdoc = hdoc.content
            cdocs = None

            pmap = hdoc.get(fields.PARTS_MAP_KEY, None)
            if new and pmap is not None:
                # take the different cdocs for write...
                cdoc_store = self._cdoc_store
                cdocs_list = phash_iter(hdoc)
                cdocs = dict(enumerate(
                    [cdoc_store[phash] for phash in cdocs_list], 1))

            return MessageWrapper(fdoc=fdoc, hdoc=hdoc, cdocs=cdocs,
                                  new=new, dirty=dirty,
                                  memstore=weakref.proxy(self))

    def remove_message(self, mbox, uid):
        """
        Remove a Message from this MemoryStore.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the message UID
        :type uid: int
        """
        # XXX For the moment we are only removing the flags and headers
        # docs. The rest we leave there polluting your hard disk,
        # until we think about a good way of deorphaning.

        # XXX implement elijah's idea of using a PUT document as a
        # token to ensure consistency in the removal.

        try:
            del self._fdoc_store[mbox][uid]
        except KeyError:
            pass

        try:
            key = mbox, uid
            self._new.discard(key)
            self._dirty.discard(key)
            if key in self._sizes:
                del self._sizes[key]
            self._known_uids[mbox].discard(uid)
        except KeyError:
            pass
        except Exception as exc:
            logger.error("error while removing message!")
            logger.exception(exc)
        try:
            with self._fdoc_docid_lock:
                del self._fdoc_id_store[mbox][uid]
        except KeyError:
            pass
        except Exception as exc:
            logger.error("error while removing message!")
            logger.exception(exc)

    # IMessageStoreWriter

    @deferred_to_thread
    def write_messages(self, store):
        """
        Write the message documents in this MemoryStore to a different store.

        :param store: the IMessageStore to write to
        :rtype: False if queue is not empty, None otherwise.
        """
        # For now, we pass if the queue is not empty, to avoid duplicate
        # queuing.
        # We would better use a flag to know when we've already enqueued an
        # item.

        # XXX this could return the deferred for all the enqueued operations

        if not self.producer.is_queue_empty():
            return False

        if any(map(lambda i: not empty(i), (self._new, self._dirty))):
            logger.info("Writing messages to Soledad...")

        # TODO change for lock, and make the property access
        # is accquired
        with set_bool_flag(self, self.WRITING_FLAG):
            for rflags_doc_wrapper in self.all_rdocs_iter():
                self.producer.push(rflags_doc_wrapper,
                                   state=self.producer.STATE_DIRTY)
            for msg_wrapper in self.all_new_msg_iter():
                self.producer.push(msg_wrapper,
                                   state=self.producer.STATE_NEW)
            for msg_wrapper in self.all_dirty_msg_iter():
                self.producer.push(msg_wrapper,
                                   state=self.producer.STATE_DIRTY)

    # MemoryStore specific methods.

    def get_uids(self, mbox):
        """
        Get all uids for a given mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: list
        """
        return self._fdoc_store[mbox].keys()

    def get_soledad_known_uids(self, mbox):
        """
        Get all uids that soledad knows about, from the memory cache.
        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: list
        """
        return self._known_uids.get(mbox, [])

    # last_uid

    def get_last_uid(self, mbox):
        """
        Return the highest UID for a given mbox.
        It will be the highest between the highest uid in the message store for
        the mailbox, and the soledad integer cache.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: int
        """
        uids = self.get_uids(mbox)
        last_mem_uid = uids and max(uids) or 0
        last_soledad_uid = self.get_last_soledad_uid(mbox)
        return max(last_mem_uid, last_soledad_uid)

    def get_last_soledad_uid(self, mbox):
        """
        Get last uid for a given mbox from the soledad integer cache.

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        return self._last_uid.get(mbox, 0)

    def set_last_soledad_uid(self, mbox, value):
        """
        Set last uid for a given mbox in the soledad integer cache.
        SoledadMailbox should prime this value during initialization.
        Other methods (during message adding) SHOULD call
        `increment_last_soledad_uid` instead.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param value: the value to set
        :type value: int
        """
        # can be long???
        #leap_assert_type(value, int)
        logger.info("setting last soledad uid for %s to %s" %
                    (mbox, value))
        # if we already have a value here, don't do anything
        with self._last_uid_lock:
            if not self._last_uid.get(mbox, None):
                self._last_uid[mbox] = value

    def set_known_uids(self, mbox, value):
        """
        Set the value fo the known-uids set for this mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param value: a sequence of integers to be added to the set.
        :type value: tuple
        """
        current = self._known_uids[mbox]
        self._known_uids[mbox] = current.union(set(value))

    def increment_last_soledad_uid(self, mbox):
        """
        Increment by one the soledad integer cache for the last_uid for
        this mbox, and fire a defer-to-thread to update the soledad value.
        The caller should lock the call tho this method.

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        with self._last_uid_lock:
            self._last_uid[mbox] += 1
            value = self._last_uid[mbox]
            self.reactor.callInThread(self.write_last_uid, mbox, value)
            return value

    def write_last_uid(self, mbox, value):
        """
        Increment the soledad integer cache for the highest uid value.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param value: the value to set
        :type value: int
        """
        leap_assert_type(value, int)
        if self._permanent_store:
            self._permanent_store.write_last_uid(mbox, value)

    def load_flag_docs(self, mbox, flag_docs):
        """
        Load the flag documents for the given mbox.
        Used during initial flag docs prefetch.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param flag_docs: a dict with the content for the flag docs, indexed
                          by uid.
        :type flag_docs: dict
        """
        # We can do direct assignments cause we know this will only
        # be called during initialization of the mailbox.
        # TODO could hook here a sanity-check
        # for duplicates

        fdoc_store = self._fdoc_store[mbox]
        chash_fdoc_store = self._chash_fdoc_store
        for uid in flag_docs:
            rdict = ReferenciableDict(flag_docs[uid])
            fdoc_store[uid] = rdict
            # populate chash dict too, to avoid fdoc duplication
            chash = flag_docs[uid]["chash"]
            chash_fdoc_store[chash][mbox] = weakref.proxy(
                self._fdoc_store[mbox][uid])

    def update_flags(self, mbox, uid, fdoc):
        """
        Update the flag document for a given mbox and uid combination,
        and set the dirty flag.
        We could use put_message, but this is faster.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the uid of the message
        :type uid: int

        :param fdoc: a dict with the content for the flag docs
        :type fdoc: dict
        """
        key = mbox, uid
        self._fdoc_store[mbox][uid].update(fdoc)
        self._dirty.add(key)

    def load_header_docs(self, header_docs):
        """
        Load the flag documents for the given mbox.
        Used during header docs prefetch, and during cache after
        a read from soledad if the hdoc property in message did not
        find its value in here.

        :param flag_docs: a dict with the content for the flag docs.
        :type flag_docs: dict
        """
        hdoc_store = self._hdoc_store
        for chash in header_docs:
            hdoc_store[chash] = ReferenciableDict(header_docs[chash])

    def all_flags(self, mbox):
        """
        Return a dictionary with all the flags for a given mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: dict
        """
        fdict = {}
        uids = self.get_uids(mbox)
        fstore = self._fdoc_store[mbox]

        for uid in uids:
            try:
                fdict[uid] = fstore[uid][fields.FLAGS_KEY]
            except KeyError:
                continue
        return fdict

    def all_headers(self, mbox):
        """
        Return a dictionary with all the header docs for a given mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: dict
        """
        headers_dict = {}
        uids = self.get_uids(mbox)
        fdoc_store = self._fdoc_store[mbox]
        hdoc_store = self._hdoc_store

        for uid in uids:
            try:
                chash = fdoc_store[uid][fields.CONTENT_HASH_KEY]
                hdoc = hdoc_store[chash]
                if not empty(hdoc):
                    headers_dict[uid] = hdoc
            except KeyError:
                continue
        return headers_dict

    # Counting sheeps...

    def count_new_mbox(self, mbox):
        """
        Count the new messages by mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: number of new messages
        :rtype: int
        """
        return len([(m, uid) for m, uid in self._new if mbox == mbox])

    # XXX used at all?
    def count_new(self):
        """
        Count all the new messages in the MemoryStore.

        :rtype: int
        """
        return len(self._new)

    def count(self, mbox):
        """
        Return the count of messages for a given mbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: number of messages
        :rtype: int
        """
        return len(self._fdoc_store[mbox])

    def unseen_iter(self, mbox):
        """
        Get an iterator for the message UIDs with no `seen` flag
        for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: iterator through unseen message doc UIDs
        :rtype: iterable
        """
        fdocs = self._fdoc_store[mbox]

        return [uid for uid, value
                in fdocs.items()
                if fields.SEEN_FLAG not in value.get(fields.FLAGS_KEY, [])]

    def get_cdoc_from_phash(self, phash):
        """
        Return a content-document by its payload-hash.

        :param phash: the payload hash to check against
        :type phash: str or unicode
        :rtype: MessagePartDoc
        """
        doc = self._cdoc_store.get(phash, None)

        # XXX return None for consistency?

        # XXX have to keep a mapping between phash and its linkage
        # info, to know if this payload is been already saved or not.
        # We will be able to get this from the linkage-docs,
        # not yet implemented.
        new = True
        dirty = False
        return MessagePartDoc(
            new=new, dirty=dirty, store="mem",
            part=MessagePartType.cdoc,
            content=doc,
            doc_id=None)

    def get_fdoc_from_chash(self, chash, mbox):
        """
        Return a flags-document by its content-hash and a given mailbox.
        Used during content-duplication detection while copying or adding a
        message.

        :param chash: the content hash to check against
        :type chash: str or unicode
        :param mbox: the mailbox
        :type mbox: str or unicode

        :return: MessagePartDoc. It will return None if the flags document
                 has empty content or it is flagged as \\Deleted.
        """
        fdoc = self._chash_fdoc_store[chash][mbox]

        # a couple of special cases.
        # 1. We might have a doc with empty content...
        if empty(fdoc):
            return None

        # 2. ...Or the message could exist, but being flagged for deletion.
        # We want to create a new one in this case.
        # Hmmm what if the deletion is un-done?? We would end with a
        # duplicate...
        if fdoc and fields.DELETED_FLAG in fdoc.get(fields.FLAGS_KEY, []):
            return None

        uid = fdoc[fields.UID_KEY]
        key = mbox, uid
        new = key in self._new
        dirty = key in self._dirty

        return MessagePartDoc(
            new=new, dirty=dirty, store="mem",
            part=MessagePartType.fdoc,
            content=fdoc,
            doc_id=None)

    def iter_fdoc_keys(self):
        """
        Return a generator through all the mbox, uid keys in the flags-doc
        store.
        """
        fdoc_store = self._fdoc_store
        for mbox in fdoc_store:
            for uid in fdoc_store[mbox]:
                yield mbox, uid

    def all_new_msg_iter(self):
        """
        Return generator that iterates through all new messages.

        :return: generator of MessageWrappers
        :rtype: generator
        """
        gm = self.get_message
        # need to freeze, set can change during iteration
        new = [gm(*key, dirtystate=DirtyState.new) for key in tuple(self._new)]
        # move content from new set to the queue
        self._new_queue.update(self._new)
        self._new.difference_update(self._new)
        return new

    def all_dirty_msg_iter(self):
        """
        Return generator that iterates through all dirty messages.

        :return: generator of MessageWrappers
        :rtype: generator
        """
        gm = self.get_message
        # need to freeze, set can change during iteration
        dirty = [gm(*key, flags_only=True, dirtystate=DirtyState.dirty)
                 for key in tuple(self._dirty)]
        # move content from new and dirty sets to the queue

        self._dirty_queue.update(self._dirty)
        self._dirty.difference_update(self._dirty)
        return dirty

    def all_deleted_uid_iter(self, mbox):
        """
        Return a list with the UIDs for all messags
        with deleted flag in a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: list of integers
        :rtype: list
        """
        # This *needs* to return a fixed sequence. Otherwise the dictionary len
        # will change during iteration, when we modify it
        fdocs = self._fdoc_store[mbox]
        return [uid for uid, value
                in fdocs.items()
                if fields.DELETED_FLAG in value.get(fields.FLAGS_KEY, [])]

    # new, dirty flags

    def _get_new_dirty_state(self, key):
        """
        Return `new` and `dirty` flags for a given message.

        :param key: the key for the message, in the form mbox, uid
        :type key: tuple
        :return: tuple of bools
        :rtype: tuple
        """
        # TODO change indexing of sets to [mbox][key] too.
        # XXX should return *first* the news, and *then* the dirty...

        # TODO should query in queues too , true?
        #
        return map(lambda _set: key in _set, (self._new, self._dirty))

    def set_new_queued(self, key):
        """
        Add the key value to the `new-queue` set.

        :param key: the key for the message, in the form mbox, uid
        :type key: tuple
        """
        self._new_queue.add(key)

    def unset_new_queued(self, key):
        """
        Remove the key value from the `new-queue` set.

        :param key: the key for the message, in the form mbox, uid
        :type key: tuple
        """
        self._new_queue.discard(key)
        deferreds = self._new_deferreds
        d = deferreds.get(key, None)
        if d:
            # XXX use a namedtuple for passing the result
            # when we check it in the other side.
            d.callback('%s, ok' % str(key))
            deferreds.pop(key)

    def set_dirty_queued(self, key):
        """
        Add the key value to the `dirty-queue` set.

        :param key: the key for the message, in the form mbox, uid
        :type key: tuple
        """
        self._dirty_queue.add(key)

    def unset_dirty_queued(self, key):
        """
        Remove the key value from the `dirty-queue` set.

        :param key: the key for the message, in the form mbox, uid
        :type key: tuple
        """
        self._dirty_queue.discard(key)
        deferreds = self._dirty_deferreds
        d = deferreds.get(key, None)
        if d:
            # XXX use a namedtuple for passing the result
            # when we check it in the other side.
            d.callback('%s, ok' % str(key))
            deferreds.pop(key)

    # Recent Flags

    def set_recent_flag(self, mbox, uid):
        """
        Set the `Recent` flag for a given mailbox and UID.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the message UID
        :type uid: int
        """
        self._rflags_dirty.add(mbox)
        self._rflags_store[mbox]['set'].add(uid)

    # TODO --- nice but unused
    def unset_recent_flag(self, mbox, uid):
        """
        Unset the `Recent` flag for a given mailbox and UID.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param uid: the message UID
        :type uid: int
        """
        self._rflags_store[mbox]['set'].discard(uid)

    def set_recent_flags(self, mbox, value):
        """
        Set the value for the set of the recent flags.
        Used from the property in the MessageCollection.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param value: a sequence of flags to set
        :type value: sequence
        """
        self._rflags_dirty.add(mbox)
        self._rflags_store[mbox]['set'] = set(value)

    def load_recent_flags(self, mbox, flags_doc):
        """
        Load the passed flags document in the recent flags store, for a given
        mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param flags_doc: A dictionary containing the `doc_id` of the Soledad
                          flags-document for this mailbox, and the `set`
                          of uids marked with that flag.
        """
        self._rflags_store[mbox] = flags_doc

    def get_recent_flags(self, mbox):
        """
        Return the set of UIDs with the `Recent` flag for this mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: set, or None
        """
        rflag_for_mbox = self._rflags_store.get(mbox, None)
        if not rflag_for_mbox:
            return None
        return self._rflags_store[mbox]['set']

    def all_rdocs_iter(self):
        """
        Return an iterator through all in-memory recent flag dicts, wrapped
        under a RecentFlagsDoc namedtuple.
        Used for saving to disk.

        :return: a generator of RecentFlagDoc
        :rtype: generator
        """
        # XXX use enums
        DOC_ID = "doc_id"
        SET = "set"

        rflags_store = self._rflags_store

        def get_rdoc(mbox, rdict):
            mbox_rflag_set = rdict[SET]
            recent_set = copy(mbox_rflag_set)
            # zero it!
            mbox_rflag_set.difference_update(mbox_rflag_set)
            return RecentFlagsDoc(
                doc_id=rflags_store[mbox][DOC_ID],
                content={
                    fields.TYPE_KEY: fields.TYPE_RECENT_VAL,
                    fields.MBOX_KEY: mbox,
                    fields.RECENTFLAGS_KEY: list(recent_set)
                })

        return (get_rdoc(mbox, rdict) for mbox, rdict in rflags_store.items()
                if not empty(rdict[SET]))

    # Methods that mirror the IMailbox interface

    def remove_all_deleted(self, mbox):
        """
        Remove all messages flagged \\Deleted from this Memory Store only.
        Called from `expunge`

        :param mbox: the mailbox
        :type mbox: str or unicode
        :return: a list of UIDs
        :rtype: list
        """
        mem_deleted = self.all_deleted_uid_iter(mbox)
        for uid in mem_deleted:
            self.remove_message(mbox, uid)
        return mem_deleted

    def stop_and_flush(self):
        """
        Stop the write loop and trigger a write to the producer.
        """
        self._stop_write_loop()
        if self._permanent_store is not None:
            # XXX we should check if we did get a True value on this
            # operation. If we got False we should retry! (queue was not empty)
            self.write_messages(self._permanent_store)
            self.producer.flush()

    def expunge(self, mbox, observer):
        """
        Remove all messages flagged \\Deleted, from the Memory Store
        and from the permanent store also.

        It first queues up a last write, and wait for the deferreds to be done
        before continuing.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param observer: a deferred that will be fired when expunge is done
        :type observer: Deferred
        """
        soledad_store = self._permanent_store
        if soledad_store is None:
            # just-in memory store, easy then.
            self._delete_from_memory(mbox, observer)
            return

        # We have a soledad storage.
        try:
            # Stop and trigger last write
            self.stop_and_flush()
            # Wait on the writebacks to finish

            # XXX what if pending deferreds is empty?
            pending_deferreds = (self._new_deferreds.get(mbox, []) +
                                 self._dirty_deferreds.get(mbox, []))
            d1 = defer.gatherResults(pending_deferreds, consumeErrors=True)
            d1.addCallback(
                self._delete_from_soledad_and_memory, mbox, observer)
        except Exception as exc:
            logger.exception(exc)

    def _delete_from_memory(self, mbox, observer):
        """
        Remove all messages marked as deleted from soledad and memory.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :param observer: a deferred that will be fired when expunge is done
        :type observer: Deferred
        """
        mem_deleted = self.remove_all_deleted(mbox)
        observer.callback(mem_deleted)

    def _delete_from_soledad_and_memory(self, result, mbox, observer):
        """
        Remove all messages marked as deleted from soledad and memory.

        :param result: ignored. the result of the deferredList that triggers
                       this as a callback from `expunge`.
        :param mbox: the mailbox
        :type mbox: str or unicode
        :param observer: a deferred that will be fired when expunge is done
        :type observer: Deferred
        """
        all_deleted = []
        soledad_store = self._permanent_store

        try:
            # 1. Delete all messages marked as deleted in soledad.
            logger.debug("DELETING FROM SOLEDAD ALL FOR %r" % (mbox,))
            sol_deleted = soledad_store.remove_all_deleted(mbox)

            try:
                self._known_uids[mbox].difference_update(set(sol_deleted))
            except Exception as exc:
                logger.exception(exc)

            # 2. Delete all messages marked as deleted in memory.
            logger.debug("DELETING FROM MEM ALL FOR %r" % (mbox,))
            mem_deleted = self.remove_all_deleted(mbox)

            all_deleted = set(mem_deleted).union(set(sol_deleted))
            logger.debug("deleted %r" % all_deleted)
        except Exception as exc:
            logger.exception(exc)
        finally:
            self._start_write_loop()

        observer.callback(all_deleted)

    # Mailbox documents and attributes

    # This could be also be cached in memstore, but proxying directly
    # to soledad since it's not too performance-critical.

    def get_mbox_doc(self, mbox):
        """
        Return the soledad document for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: SoledadDocument or None.
        """
        return self.permanent_store.get_mbox_document(mbox)

    def get_mbox_closed(self, mbox):
        """
        Return the closed attribute for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        :rtype: bool
        """
        return self.permanent_store.get_mbox_closed(mbox)

    def set_mbox_closed(self, mbox, closed):
        """
        Set the closed attribute for a given mailbox.

        :param mbox: the mailbox
        :type mbox: str or unicode
        """
        self.permanent_store.set_mbox_closed(mbox, closed)

    # Rename flag-documents

    def rename_fdocs_mailbox(self, old_mbox, new_mbox):
        """
        Change the mailbox name for all flag documents in a given mailbox.
        Used from account.rename

        :param old_mbox: name for the old mbox
        :type old_mbox: str or unicode
        :param new_mbox: name for the new mbox
        :type new_mbox: str or unicode
        """
        fs = self._fdoc_store
        keys = fs[old_mbox].keys()
        for k in keys:
            fdoc = fs[old_mbox][k]
            fdoc['mbox'] = new_mbox
            fs[new_mbox][k] = fdoc
            fs[old_mbox].pop(k)
            self._dirty.add((new_mbox, k))

    # Dump-to-disk controls.

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
        # FIXME this should return a deferred !!!
        # XXX ----- can fire when all new + dirty deferreds
        # are done (gatherResults)
        return getattr(self, self.WRITING_FLAG)

    @property
    def permanent_store(self):
        return self._permanent_store

    # Memory management.

    def get_size(self):
        """
        Return the size of the internal storage.
        Use for calculating the limit beyond which we should flush the store.

        :rtype: int
        """
        return reduce(lambda x, y: x + y, self._sizes, 0)
