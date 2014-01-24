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

from twisted.internet import defer
from twisted.internet.task import LoopingCall
from twisted.python import log
from zope.interface import implements

from leap.mail import size
from leap.mail.utils import empty
from leap.mail.messageflow import MessageProducer
from leap.mail.imap import interfaces
from leap.mail.imap.fields import fields
from leap.mail.imap.messageparts import MessagePartType, MessagePartDoc
from leap.mail.imap.messageparts import MessageWrapper
from leap.mail.imap.messageparts import ReferenciableDict

logger = logging.getLogger(__name__)

SOLEDAD_WRITE_PERIOD = 20


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
    implements(interfaces.IMessageStore,
               interfaces.IMessageStoreWriter)

    producer = None

    # TODO We will want to index by chash when we transition to local-only
    # UIDs.
    # TODO should store RECENT-FLAGS too
    # TODO should store HDOCSET too (use weakrefs!) -- will need to subclass
    # TODO do use dirty flag (maybe use namedtuples for that) so we can use it
    # also as a read-cache.

    WRITING_FLAG = "_writing"

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
        self._permanent_store = permanent_store
        self._write_period = write_period

        # Internal Storage: messages
        self._msg_store = {}

        # Internal Storage: payload-hash
        """
        {'phash': weakreaf.proxy(dict)}
        """
        self._phash_store = {}

        # Internal Storage: content-hash:fdoc
        """
        {'chash': {'mbox-a': weakref.proxy(dict),
                   'mbox-b': weakref.proxy(dict)}
        }
        """
        self._chash_fdoc_store = {}

        # TODO ----------------- implement mailbox-level flags store too! ----
        self._rflags_store = {}
        self._hdocset_store = {}
        # TODO ----------------- implement mailbox-level flags store too! ----

        # New and dirty flags, to set MessageWrapper State.
        self._new = set([])
        self._new_deferreds = {}
        self._dirty = set([])
        self._dirty_deferreds = {}

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

    def create_message(self, mbox, uid, message, notify_on_disk=True):
        """
        Create the passed message into this MemoryStore.

        By default we consider that any message is a new message.

        :param mbox: the mailbox
        :type mbox: basestring
        :param uid: the UID for the message
        :type uid: int
        :param message: a to be added
        :type message: MessageWrapper
        :param notify_on_disk:
        :type notify_on_disk: bool

        :return: a Deferred. if notify_on_disk is True, will be fired
                 when written to the db on disk.
                 Otherwise will fire inmediately
        :rtype: Deferred
        """
        print "adding new doc to memstore %s (%s)" % (mbox, uid)
        key = mbox, uid

        d = defer.Deferred()
        d.addCallback(lambda result: log.msg("message save: %s" % result))

        self._new.add(key)
        self._new_deferreds[key] = d
        self._add_message(mbox, uid, message, notify_on_disk)
        print "create message: ", d
        return d

    def put_message(self, mbox, uid, message, notify_on_disk=True):
        """
        Put an existing message.

        :param mbox: the mailbox
        :type mbox: basestring
        :param uid: the UID for the message
        :type uid: int
        :param message: a to be added
        :type message: MessageWrapper
        :param notify_on_disk:
        :type notify_on_disk: bool

        :return: a Deferred. if notify_on_disk is True, will be fired
                 when written to the db on disk.
                 Otherwise will fire inmediately
        :rtype: Deferred
        """
        key = mbox, uid

        d = defer.Deferred()
        d.addCallback(lambda result: log.msg("message save: %s" % result))

        self._dirty.add(key)
        self._dirty_deferreds[key] = d
        self._add_message(mbox, uid, message, notify_on_disk)
        return d

    def _add_message(self, mbox, uid, message, notify_on_disk=True):
        # XXX have to differentiate between notify_new and notify_dirty

        key = mbox, uid
        msg_dict = message.as_dict()
        print "ADDING MESSAGE..."
        import pprint; pprint.pprint(msg_dict)

        # XXX use the enum as keys

        try:
            store = self._msg_store[key]
        except KeyError:
            self._msg_store[key] = {'fdoc': {},
                                    'hdoc': {},
                                    'cdocs': {},
                                    'docs_id': {}}
            store = self._msg_store[key]

        print "In store (before):"
        import pprint; pprint.pprint(store)

        #self._msg_store[key] = msg_dict
        fdoc = msg_dict.get('fdoc', None)
        if fdoc:
            if not store.get('fdoc', None):
                store['fdoc'] = ReferenciableDict({})
            store['fdoc'].update(fdoc)

            # content-hash indexing
            chash = fdoc.get(fields.CONTENT_HASH_KEY)
            chash_fdoc_store = self._chash_fdoc_store
            if not chash in chash_fdoc_store:
                chash_fdoc_store[chash] = {}

            chash_fdoc_store[chash][mbox] = weakref.proxy(
                store['fdoc'])

        hdoc = msg_dict.get('hdoc', None)
        if hdoc:
            if not store.get('hdoc', None):
                store['hdoc'] = ReferenciableDict({})
            store['hdoc'].update(hdoc)

        docs_id = msg_dict.get('docs_id', None)
        if docs_id:
            if not store.get('docs_id', None):
                store['docs_id'] = {}
            store['docs_id'].update(docs_id)

        cdocs = message.cdocs
        for cdoc_key in cdocs.keys():
            if not store.get('cdocs', None):
                store['cdocs'] = {}

            cdoc = cdocs[cdoc_key]
            # first we make it weak-referenciable
            referenciable_cdoc = ReferenciableDict(cdoc)
            store['cdocs'][cdoc_key] = referenciable_cdoc
            phash = cdoc.get(fields.PAYLOAD_HASH_KEY, None)
            if not phash:
                continue
            self._phash_store[phash] = weakref.proxy(referenciable_cdoc)

        def prune(seq, store):
            for key in seq:
                if key in store and empty(store.get(key)):
                    store.pop(key)

        prune(('fdoc', 'hdoc', 'cdocs', 'docs_id'), store)
        #import ipdb; ipdb.set_trace()


        print "after appending to store: ", key
        import pprint; pprint.pprint(self._msg_store[key])

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
        try:
            key = mbox, uid
            self._new.discard(key)
            self._dirty.discard(key)
            self._msg_store.pop(key, None)
        except Exception as exc:
            logger.exception(exc)

    # IMessageStoreWriter

    def write_messages(self, store):
        """
        Write the message documents in this MemoryStore to a different store.
        """
        # For now, we pass if the queue is not empty, to avoid duplication.
        # We would better use a flag to know when we've already enqueued an
        # item.
        if not self.producer.is_queue_empty():
            return

        print "Writing messages to Soledad..."
        with set_bool_flag(self, self.WRITING_FLAG):
            for msg_wrapper in self.all_new_dirty_msg_iter():
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
        uids = self.get_uids(mbox)
        return uids and max(uids) or 0

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

    def get_cdoc_from_phash(self, phash):
        """
        Return a content-document by its payload-hash.
        """
        doc = self._phash_store.get(phash, None)

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

        :return: MessagePartDoc, or None.
        """
        docs_dict = self._chash_fdoc_store.get(chash, None)
        fdoc = docs_dict.get(mbox, None) if docs_dict else None

        print "GETTING FDOC BY CHASH:", fdoc

        # a couple of special cases.
        # 1. We might have a doc with empty content...
        if empty(fdoc):
            return None

        # ...Or the message could exist, but being flagged for deletion.
        # We want to create a new one in this case.
        # Hmmm what if the deletion is un-done?? We would end with a
        # duplicate...
        if fdoc and fields.DELETED_FLAG in fdoc[fields.FLAGS_KEY]:
            return None

        # XXX get flags
        new = True
        dirty = False
        return MessagePartDoc(
            new=new, dirty=dirty, store="mem",
            part=MessagePartType.fdoc,
            content=fdoc,
            doc_id=None)

    def all_msg_iter(self):
        """
        Return generator that iterates through all messages in the store.
        """
        return (self.get_message(*key)
                for key in sorted(self._msg_store.keys()))

    def all_new_dirty_msg_iter(self):
        """
        Return geneator that iterates through all new and dirty messages.
        """
        return (self.get_message(*key)
                for key in sorted(self._msg_store.keys())
                if key in self._new or key in self._dirty)

    def all_deleted_uid_iter(self, mbox):
        """
        Return generator that iterates through the UIDs for all messags
        with deleted flag in a given mailbox.
        """
        all_deleted = (
            msg['fdoc']['uid'] for msg in self._msg_store.values()
            if msg.get('fdoc', None)
            and fields.DELETED_FLAG in msg['fdoc']['flags'])
        return all_deleted

    # new, dirty flags

    def _get_new_dirty_state(self, key):
        """
        Return `new` and `dirty` flags for a given message.
        """
        return map(lambda _set: key in _set, (self._new, self._dirty))

    def set_new(self, key):
        """
        Add the key value to the `new` set.
        """
        self._new.add(key)

    def unset_new(self, key):
        """
        Remove the key value from the `new` set.
        """
        print "Unsetting NEW for: %s" % str(key)
        self._new.discard(key)
        deferreds = self._new_deferreds
        d = deferreds.get(key, None)
        if d:
            # XXX use a namedtuple for passing the result
            # when we check it in the other side.
            d.callback('%s, ok' % str(key))
            deferreds.pop(key)

    def set_dirty(self, key):
        """
        Add the key value to the `dirty` set.
        """
        self._dirty.add(key)

    def unset_dirty(self, key):
        """
        Remove the key value from the `dirty` set.
        """
        print "Unsetting DIRTY for: %s" % str(key)
        self._dirty.discard(key)
        deferreds = self._dirty_deferreds
        d = deferreds.get(key, None)
        if d:
            # XXX use a namedtuple for passing the result
            # when we check it in the other side.
            d.callback('%s, ok' % str(key))
            deferreds.pop(key)

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
