# *- coding: utf-8 -*-
# mailbox.py
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
Soledad Mailbox.
"""
import copy
import threading
import logging
import time
import StringIO
import cStringIO

from collections import defaultdict

from twisted.internet import defer
from twisted.python import log

from twisted.mail import imap4
from zope.interface import implements

from leap.common import events as leap_events
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL
from leap.common.check import leap_assert, leap_assert_type
from leap.mail.decorators import deferred
from leap.mail.imap.fields import WithMsgFields, fields
from leap.mail.imap.messages import MessageCollection
from leap.mail.imap.parser import MBoxParser

logger = logging.getLogger(__name__)


class SoledadMailbox(WithMsgFields, MBoxParser):
    """
    A Soledad-backed IMAP mailbox.

    Implements the high-level method needed for the Mailbox interfaces.
    The low-level database methods are contained in MessageCollection class,
    which we instantiate and make accessible in the `messages` attribute.
    """
    implements(
        imap4.IMailbox,
        imap4.IMailboxInfo,
        imap4.ICloseableMailbox,
        imap4.IMessageCopier)

    # XXX should finish the implementation of IMailboxListener
    # XXX should implement ISearchableMailbox too

    messages = None
    _closed = False

    INIT_FLAGS = (WithMsgFields.SEEN_FLAG, WithMsgFields.ANSWERED_FLAG,
                  WithMsgFields.FLAGGED_FLAG, WithMsgFields.DELETED_FLAG,
                  WithMsgFields.DRAFT_FLAG, WithMsgFields.RECENT_FLAG,
                  WithMsgFields.LIST_FLAG)
    flags = None

    CMD_MSG = "MESSAGES"
    CMD_RECENT = "RECENT"
    CMD_UIDNEXT = "UIDNEXT"
    CMD_UIDVALIDITY = "UIDVALIDITY"
    CMD_UNSEEN = "UNSEEN"

    _listeners = defaultdict(set)
    next_uid_lock = threading.Lock()

    def __init__(self, mbox, soledad=None, rw=1):
        """
        SoledadMailbox constructor. Needs to get passed a name, plus a
        Soledad instance.

        :param mbox: the mailbox name
        :type mbox: str

        :param soledad: a Soledad instance.
        :type soledad: Soledad

        :param rw: read-and-write flags
        :type rw: int
        """
        leap_assert(mbox, "Need a mailbox name to initialize")
        leap_assert(soledad, "Need a soledad instance to initialize")

        # XXX should move to wrapper
        #leap_assert(isinstance(soledad._db, SQLCipherDatabase),
                    #"soledad._db must be an instance of SQLCipherDatabase")

        self.mbox = self._parse_mailbox_name(mbox)
        self.rw = rw

        self._soledad = soledad

        self.messages = MessageCollection(
            mbox=mbox, soledad=self._soledad)

        if not self.getFlags():
            self.setFlags(self.INIT_FLAGS)

    @property
    def listeners(self):
        """
        Returns listeners for this mbox.

        The server itself is a listener to the mailbox.
        so we can notify it (and should!) after changes in flags
        and number of messages.

        :rtype: set
        """
        return self._listeners[self.mbox]

    def addListener(self, listener):
        """
        Adds a listener to the listeners queue.
        The server adds itself as a listener when there is a SELECT,
        so it can send EXIST commands.

        :param listener: listener to add
        :type listener: an object that implements IMailboxListener
        """
        logger.debug('adding mailbox listener: %s' % listener)
        self.listeners.add(listener)

    def removeListener(self, listener):
        """
        Removes a listener from the listeners queue.

        :param listener: listener to remove
        :type listener: an object that implements IMailboxListener
        """
        self.listeners.remove(listener)

    def _get_mbox(self):
        """
        Returns mailbox document.

        :return: A SoledadDocument containing this mailbox, or None if
                 the query failed.
        :rtype: SoledadDocument or None.
        """
        try:
            query = self._soledad.get_from_index(
                fields.TYPE_MBOX_IDX,
                fields.TYPE_MBOX_VAL, self.mbox)
            if query:
                return query.pop()
        except Exception as exc:
            logger.error("Unhandled error %r" % exc)

    def getFlags(self):
        """
        Returns the flags defined for this mailbox.

        :returns: tuple of flags for this mailbox
        :rtype: tuple of str
        """
        mbox = self._get_mbox()
        if not mbox:
            return None
        flags = mbox.content.get(self.FLAGS_KEY, [])
        return map(str, flags)

    def setFlags(self, flags):
        """
        Sets flags for this mailbox.

        :param flags: a tuple with the flags
        :type flags: tuple of str
        """
        leap_assert(isinstance(flags, tuple),
                    "flags expected to be a tuple")
        mbox = self._get_mbox()
        if not mbox:
            return None
        mbox.content[self.FLAGS_KEY] = map(str, flags)
        self._soledad.put_doc(mbox)

    # XXX SHOULD BETTER IMPLEMENT ADD_FLAG, REMOVE_FLAG.

    def _get_closed(self):
        """
        Return the closed attribute for this mailbox.

        :return: True if the mailbox is closed
        :rtype: bool
        """
        mbox = self._get_mbox()
        return mbox.content.get(self.CLOSED_KEY, False)

    def _set_closed(self, closed):
        """
        Set the closed attribute for this mailbox.

        :param closed: the state to be set
        :type closed: bool
        """
        leap_assert(isinstance(closed, bool), "closed needs to be boolean")
        mbox = self._get_mbox()
        mbox.content[self.CLOSED_KEY] = closed
        self._soledad.put_doc(mbox)

    closed = property(
        _get_closed, _set_closed, doc="Closed attribute.")

    def _get_last_uid(self):
        """
        Return the last uid for this mailbox.

        :return: the last uid for messages in this mailbox
        :rtype: bool
        """
        mbox = self._get_mbox()
        return mbox.content.get(self.LAST_UID_KEY, 1)

    def _set_last_uid(self, uid):
        """
        Sets the last uid for this mailbox.

        :param uid: the uid to be set
        :type uid: int
        """
        leap_assert(isinstance(uid, int), "uid has to be int")
        mbox = self._get_mbox()
        key = self.LAST_UID_KEY

        count = self.getMessageCount()

        # XXX safety-catch. If we do get duplicates,
        # we want to avoid further duplication.

        if uid >= count:
            value = uid
        else:
            # something is wrong,
            # just set the last uid
            # beyond the max msg count.
            logger.debug("WRONG uid < count. Setting last uid to %s", count)
            value = count

        mbox.content[key] = value
        self._soledad.put_doc(mbox)

    last_uid = property(
        _get_last_uid, _set_last_uid, doc="Last_UID attribute.")

    def getUIDValidity(self):
        """
        Return the unique validity identifier for this mailbox.

        :return: unique validity identifier
        :rtype: int
        """
        mbox = self._get_mbox()
        return mbox.content.get(self.CREATED_KEY, 1)

    def getUID(self, message):
        """
        Return the UID of a message in the mailbox

        .. note:: this implementation does not make much sense RIGHT NOW,
        but in the future will be useful to get absolute UIDs from
        message sequence numbers.

        :param message: the message uid
        :type message: int

        :rtype: int
        """
        msg = self.messages.get_msg_by_uid(message)
        return msg.getUID()

    def getUIDNext(self):
        """
        Return the likely UID for the next message added to this
        mailbox. Currently it returns the higher UID incremented by
        one.

        We increment the next uid *each* time this function gets called.
        In this way, there will be gaps if the message with the allocated
        uid cannot be saved. But that is preferable to having race conditions
        if we get to parallel message adding.

        :rtype: int
        """
        with self.next_uid_lock:
            self.last_uid += 1
            return self.last_uid

    def getMessageCount(self):
        """
        Returns the total count of messages in this mailbox.

        :rtype: int
        """
        return self.messages.count()

    def getUnseenCount(self):
        """
        Returns the number of messages with the 'Unseen' flag.

        :return: count of messages flagged `unseen`
        :rtype: int
        """
        return self.messages.count_unseen()

    def getRecentCount(self):
        """
        Returns the number of messages with the 'Recent' flag.

        :return: count of messages flagged `recent`
        :rtype: int
        """
        return self.messages.count_recent()

    def isWriteable(self):
        """
        Get the read/write status of the mailbox.

        :return: 1 if mailbox is read-writeable, 0 otherwise.
        :rtype: int
        """
        return self.rw

    def getHierarchicalDelimiter(self):
        """
        Returns the character used to delimite hierarchies in mailboxes.

        :rtype: str
        """
        return '/'

    def requestStatus(self, names):
        """
        Handles a status request by gathering the output of the different
        status commands.

        :param names: a list of strings containing the status commands
        :type names: iter
        """
        r = {}
        if self.CMD_MSG in names:
            r[self.CMD_MSG] = self.getMessageCount()
        if self.CMD_RECENT in names:
            r[self.CMD_RECENT] = self.getRecentCount()
        if self.CMD_UIDNEXT in names:
            r[self.CMD_UIDNEXT] = self.last_uid + 1
        if self.CMD_UIDVALIDITY in names:
            r[self.CMD_UIDVALIDITY] = self.getUID()
        if self.CMD_UNSEEN in names:
            r[self.CMD_UNSEEN] = self.getUnseenCount()
        return defer.succeed(r)

    def addMessage(self, message, flags, date=None):
        """
        Adds a message to this mailbox.

        :param message: the raw message
        :type message: str

        :param flags: flag list
        :type flags: list of str

        :param date: timestamp
        :type date: str

        :return: a deferred that evals to None
        """
        if isinstance(message, (cStringIO.OutputType, StringIO.StringIO)):
            message = message.getvalue()
        # XXX we should treat the message as an IMessage from here
        leap_assert_type(message, basestring)
        uid_next = self.getUIDNext()
        logger.debug('Adding msg with UID :%s' % uid_next)
        if flags is None:
            flags = tuple()
        else:
            flags = tuple(str(flag) for flag in flags)

        d = self._do_add_message(message, flags, date, uid_next)
        d.addCallback(self._notify_new)
        return d

    @deferred
    def _do_add_message(self, message, flags, date, uid_next):
        """
        Calls to the messageCollection add_msg method (deferred to thread).
        Invoked from addMessage.
        """
        self.messages.add_msg(message, flags=flags, date=date,
                              uid=uid_next)

    def _notify_new(self, *args):
        """
        Notify of new messages to all the listeners.

        :param args: ignored.
        """
        exists = self.getMessageCount()
        recent = self.getRecentCount()
        logger.debug("NOTIFY: there are %s messages, %s recent" % (
            exists,
            recent))

        logger.debug("listeners: %s", str(self.listeners))
        for l in self.listeners:
            logger.debug('notifying...')
            l.newMessages(exists, recent)

    # commands, do not rename methods

    def destroy(self):
        """
        Called before this mailbox is permanently deleted.

        Should cleanup resources, and set the \\Noselect flag
        on the mailbox.
        """
        self.setFlags((self.NOSELECT_FLAG,))
        self.deleteAllDocs()

        # XXX removing the mailbox in situ for now,
        # we should postpone the removal
        self._soledad.delete_doc(self._get_mbox())

    @deferred
    def expunge(self):
        """
        Remove all messages flagged \\Deleted
        """
        if not self.isWriteable():
            raise imap4.ReadOnlyMailbox
        deleted = []
        for m in self.messages:
            if self.DELETED_FLAG in m.getFlags():
                self.messages.remove(m)
                # XXX this would ve more efficient if we can just pass
                # a sequence of uids.
                deleted.append(m.getUID())
        return deleted

    @deferred
    def fetch(self, messages, uid):
        """
        Retrieve one or more messages in this mailbox.

        from rfc 3501: The data items to be fetched can be either a single atom
        or a parenthesized list.

        :param messages: IDs of the messages to retrieve information about
        :type messages: MessageSet

        :param uid: If true, the IDs are UIDs. They are message sequence IDs
                    otherwise.
        :type uid: bool

        :rtype: A tuple of two-tuples of message sequence numbers and
                LeapMessage
        """
        result = []
        sequence = True if uid == 0 else False

        if not messages.last:
            try:
                iter(messages)
            except TypeError:
                # looks like we cannot iterate
                messages.last = self.last_uid

        # for sequence numbers (uid = 0)
        if sequence:
            logger.debug("Getting msg by index: INEFFICIENT call!")
            raise NotImplementedError

        else:
            for msg_id in messages:
                msg = self.messages.get_msg_by_uid(msg_id)
                if msg:
                    result.append((msg_id, msg))
                else:
                    logger.debug("fetch %s, no msg found!!!" % msg_id)

        if self.isWriteable():
            self._unset_recent_flag()
        self._signal_unread_to_ui()

        # XXX workaround for hangs in thunderbird
        #return tuple(result[:100])  # --- doesn't show all!!
        return tuple(result)

    @deferred
    def _unset_recent_flag(self):
        """
        Unsets `Recent` flag from a tuple of messages.
        Called from fetch.

        From RFC, about `Recent`:

        Message is "recently" arrived in this mailbox.  This session
        is the first session to have been notified about this
        message; if the session is read-write, subsequent sessions
        will not see \Recent set for this message.  This flag can not
        be altered by the client.

        If it is not possible to determine whether or not this
        session is the first session to be notified about a message,
        then that message SHOULD be considered recent.
        """
        # TODO this fucker, for the sake of correctness, is messing with
        # the whole collection of flag docs.

        # Possible ways of action:
        # 1. Ignore it, we want fun.
        # 2. Trigger it with a delay
        # 3. Route it through a queue with lesser priority than the
        #    regularar writer.

        # hmm let's try 2. in a quickndirty way...
        time.sleep(1)
        log.msg('unsetting recent flags...')
        for msg in self.messages.get_recent():
            msg.removeFlags((fields.RECENT_FLAG,))
        self._signal_unread_to_ui()

    @deferred
    def _signal_unread_to_ui(self):
        """
        Sends unread event to ui.
        """
        unseen = self.getUnseenCount()
        leap_events.signal(IMAP_UNREAD_MAIL, str(unseen))

    @deferred
    def store(self, messages, flags, mode, uid):
        """
        Sets the flags of one or more messages.

        :param messages: The identifiers of the messages to set the flags
        :type messages: A MessageSet object with the list of messages requested

        :param flags: The flags to set, unset, or add.
        :type flags: sequence of str

        :param mode: If mode is -1, these flags should be removed from the
                     specified messages.  If mode is 1, these flags should be
                     added to the specified messages.  If mode is 0, all
                     existing flags should be cleared and these flags should be
                     added.
        :type mode: -1, 0, or 1

        :param uid: If true, the IDs specified in the query are UIDs;
                    otherwise they are message sequence IDs.
        :type uid: bool

        :return: A dict mapping message sequence numbers to sequences of
                 str representing the flags set on the message after this
                 operation has been performed.
        :rtype: dict

        :raise ReadOnlyMailbox: Raised if this mailbox is not open for
                                read-write.
        """
        # XXX implement also sequence (uid = 0)
        # XXX we should prevent cclient from setting Recent flag.
        leap_assert(not isinstance(flags, basestring),
                    "flags cannot be a string")
        flags = tuple(flags)

        if not self.isWriteable():
            log.msg('read only mailbox!')
            raise imap4.ReadOnlyMailbox

        if not messages.last:
            messages.last = self.messages.count()

        result = {}
        for msg_id in messages:
            log.msg("MSG ID = %s" % msg_id)
            msg = self.messages.get_msg_by_uid(msg_id)
            if not msg:
                return result
            if mode == 1:
                msg.addFlags(flags)
            elif mode == -1:
                msg.removeFlags(flags)
            elif mode == 0:
                msg.setFlags(flags)
            result[msg_id] = msg.getFlags()

        self._signal_unread_to_ui()
        return result

    @deferred
    def close(self):
        """
        Expunge and mark as closed
        """
        self.expunge()
        self.closed = True

    # IMessageCopier

    @deferred
    def copy(self, messageObject):
        """
        Copy the given message object into this mailbox.
        """
        uid_next = self.getUIDNext()
        msg = messageObject

        # XXX should use a public api instead
        fdoc = msg._fdoc
        if not fdoc:
            logger.debug("Tried to copy a MSG with no fdoc")
            return

        new_fdoc = copy.deepcopy(fdoc.content)
        new_fdoc[self.UID_KEY] = uid_next
        new_fdoc[self.MBOX_KEY] = self.mbox

        d = self._do_add_doc(new_fdoc)
        d.addCallback(self._notify_new)

    @deferred
    def _do_add_doc(self, doc):
        """
        Defers the adding of a new doc.
        :param doc: document to be created in soledad.
        """
        self._soledad.create_doc(doc)

    # convenience fun

    def deleteAllDocs(self):
        """
        Deletes all docs in this mailbox
        """
        docs = self.messages.get_all_docs()
        for doc in docs:
            self.messages._soledad.delete_doc(doc)

    def __repr__(self):
        """
        Representation string for this mailbox.
        """
        return u"<SoledadMailbox: mbox '%s' (%s)>" % (
            self.mbox, self.messages.count())
