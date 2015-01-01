# *- coding: utf-8 -*-
# mailbox.py
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
IMAP Mailbox.
"""
import re
import logging
import StringIO
import cStringIO
import os

from collections import defaultdict

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log

from twisted.mail import imap4
from zope.interface import implements

from leap.common import events as leap_events
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL
from leap.common.check import leap_assert, leap_assert_type
from leap.mail.constants import INBOX_NAME, MessageFlags

logger = logging.getLogger(__name__)

# TODO LIST
# [ ] Restore profile_cmd instrumentation
# [ ] finish the implementation of IMailboxListener
# [ ] implement the rest of ISearchableMailbox


"""
If the environment variable `LEAP_SKIPNOTIFY` is set, we avoid
notifying clients of new messages. Use during stress tests.
"""
NOTIFY_NEW = not os.environ.get('LEAP_SKIPNOTIFY', False)
PROFILE_CMD = os.environ.get('LEAP_PROFILE_IMAPCMD', False)

if PROFILE_CMD:
    import time

    def _debugProfiling(result, cmdname, start):
        took = (time.time() - start) * 1000
        log.msg("CMD " + cmdname + " TOOK: " + str(took) + " msec")
        return result

    def do_profile_cmd(d, name):
        """
        Add the profiling debug to the passed callback.
        :param d: deferred
        :param name: name of the command
        :type name: str
        """
        d.addCallback(_debugProfiling, name, time.time())
        d.addErrback(lambda f: log.msg(f.getTraceback()))

INIT_FLAGS = (MessageFlags.SEEN_FLAG, MessageFlags.ANSWERED_FLAG,
              MessageFlags.FLAGGED_FLAG, MessageFlags.DELETED_FLAG,
              MessageFlags.DRAFT_FLAG, MessageFlags.RECENT_FLAG,
              MessageFlags.LIST_FLAG)


class IMAPMailbox(object):
    """
    A Soledad-backed IMAP mailbox.

    Implements the high-level method needed for the Mailbox interfaces.
    The low-level database methods are contained in IMAPMessageCollection
    class, which we instantiate and make accessible in the `messages`
    attribute.
    """
    implements(
        imap4.IMailbox,
        imap4.IMailboxInfo,
        imap4.ICloseableMailbox,
        imap4.ISearchableMailbox,
        imap4.IMessageCopier)

    init_flags = INIT_FLAGS

    CMD_MSG = "MESSAGES"
    CMD_RECENT = "RECENT"
    CMD_UIDNEXT = "UIDNEXT"
    CMD_UIDVALIDITY = "UIDVALIDITY"
    CMD_UNSEEN = "UNSEEN"

    # TODO we should turn this into a datastructure with limited capacity
    _listeners = defaultdict(set)

    def __init__(self, collection, rw=1):
        """
        SoledadMailbox constructor. Needs to get passed a name, plus a
        Soledad instance.

        :param collection: instance of IMAPMessageCollection
        :type collection: IMAPMessageCollection

        :param rw: read-and-write flag for this mailbox
        :type rw: int
        """
        self.rw = rw

        self._uidvalidity = None
        self.collection = collection

        if not self.getFlags():
            self.setFlags(self.init_flags)

    @property
    def mbox_name(self):
        return self.collection.mbox_name

    @property
    def listeners(self):
        """
        Returns listeners for this mbox.

        The server itself is a listener to the mailbox.
        so we can notify it (and should!) after changes in flags
        and number of messages.

        :rtype: set
        """
        return self._listeners[self.mbox_name]

    # FIXME this grows too crazily when many instances are fired, like
    # during imaptest stress testing. Should have a queue of limited size
    # instead.

    def addListener(self, listener):
        """
        Add a listener to the listeners queue.
        The server adds itself as a listener when there is a SELECT,
        so it can send EXIST commands.

        :param listener: listener to add
        :type listener: an object that implements IMailboxListener
        """
        if not NOTIFY_NEW:
            return

        logger.debug('adding mailbox listener: %s' % listener)
        self.listeners.add(listener)

    def removeListener(self, listener):
        """
        Remove a listener from the listeners queue.

        :param listener: listener to remove
        :type listener: an object that implements IMailboxListener
        """
        self.listeners.remove(listener)

    def getFlags(self):
        """
        Returns the flags defined for this mailbox.

        :returns: tuple of flags for this mailbox
        :rtype: tuple of str
        """
        flags = self.collection.mbox_wrapper.flags
        if not flags:
            flags = self.init_flags
        flags_str = map(str, flags)
        return flags_str

    def setFlags(self, flags):
        """
        Sets flags for this mailbox.

        :param flags: a tuple with the flags
        :type flags: tuple of str
        """
        # XXX this is setting (overriding) old flags.
        # Better pass a mode flag
        leap_assert(isinstance(flags, tuple),
                    "flags expected to be a tuple")
        return self.collection.set_mbox_attr("flags", flags)

    @property
    def is_closed(self):
        """
        Return the closed attribute for this mailbox.

        :return: True if the mailbox is closed
        :rtype: bool
        """
        return self.collection.get_mbox_attr("closed")

    def set_closed(self, closed):
        """
        Set the closed attribute for this mailbox.

        :param closed: the state to be set
        :type closed: bool

        :rtype: Deferred
        """
        return self.collection.set_mbox_attr("closed", closed)

    def getUIDValidity(self):
        """
        Return the unique validity identifier for this mailbox.

        :return: unique validity identifier
        :rtype: int
        """
        return self.collection.get_mbox_attr("created")

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
        d = self.collection.get_msg_by_uid(message)
        d.addCallback(lambda m: m.getUID())
        return d

    def getUIDNext(self):
        """
        Return the likely UID for the next message added to this
        mailbox. Currently it returns the higher UID incremented by
        one.

        :return: deferred with int
        :rtype: Deferred
        """
        d = self.collection.get_uid_next()
        return d

    def getMessageCount(self):
        """
        Returns the total count of messages in this mailbox.

        :return: deferred with int
        :rtype: Deferred
        """
        return self.collection.count()

    def getUnseenCount(self):
        """
        Returns the number of messages with the 'Unseen' flag.

        :return: count of messages flagged `unseen`
        :rtype: int
        """
        return self.collection.count_unseen()

    def getRecentCount(self):
        """
        Returns the number of messages with the 'Recent' flag.

        :return: count of messages flagged `recent`
        :rtype: int
        """
        return self.collection.count_recent()

    def isWriteable(self):
        """
        Get the read/write status of the mailbox.

        :return: 1 if mailbox is read-writeable, 0 otherwise.
        :rtype: int
        """
        # XXX We don't need to store it in the mbox doc, do we?
        # return int(self.collection.get_mbox_attr('rw'))
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
            r[self.CMD_UIDNEXT] = self.getUIDNext()
        if self.CMD_UIDVALIDITY in names:
            r[self.CMD_UIDVALIDITY] = self.getUIDValidity()
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
        # TODO have a look at the cases for internal date in the rfc
        if isinstance(message, (cStringIO.OutputType, StringIO.StringIO)):
            message = message.getvalue()

        # XXX we could treat the message as an IMessage from here
        leap_assert_type(message, basestring)
        if flags is None:
            flags = tuple()
        else:
            flags = tuple(str(flag) for flag in flags)

        # if PROFILE_CMD:
        # do_profile_cmd(d, "APPEND")

        # XXX should review now that we're not using qtreactor.
        # A better place for this would be  the COPY/APPEND dispatcher
        # in server.py, but qtreactor hangs when I do that, so this seems
        # to work fine for now.

        def notifyCallback(x):
            reactor.callLater(0, self.notify_new)
            return x

        d = self.collection.add_message(flags=flags, date=date)
        d.addCallback(notifyCallback)
        d.addErrback(lambda f: log.msg(f.getTraceback()))
        return d

    def notify_new(self, *args):
        """
        Notify of new messages to all the listeners.

        :param args: ignored.
        """
        if not NOTIFY_NEW:
            return

        def cbNotifyNew(result):
            exists, recent = result
            for listener in self.listeners:
                listener.newMessages(exists, recent)

        d = self._get_notify_count()
        d.addCallback(cbNotifyNew)
        d.addCallback(self.cb_signal_unread_to_ui)

    def _get_notify_count(self):
        """
        Get message count and recent count for this mailbox
        Executed in a separate thread. Called from notify_new.

        :return: a deferred that will fire with a tuple, with number of
                 messages and number of recent messages.
        :rtype: Deferred
        """
        d_exists = self.getMessageCount()
        d_recent = self.getRecentCount()
        d_list = [d_exists, d_recent]

        def log_num_msg(result):
            exists, recent = result
            logger.debug("NOTIFY (%r): there are %s messages, %s recent" % (
                         self.mbox_name, exists, recent))

        d = defer.gatherResults(d_list)
        d.addCallback(log_num_msg)
        return d

    # commands, do not rename methods

    def destroy(self):
        """
        Called before this mailbox is permanently deleted.

        Should cleanup resources, and set the \\Noselect flag
        on the mailbox.

        """
        # XXX this will overwrite all the existing flags
        # should better simply addFlag
        self.setFlags((MessageFlags.NOSELECT_FLAG,))

        def remove_mbox(_):
            # FIXME collection does not have a delete_mbox method,
            # it's in account.
            # XXX should take care of deleting the uid table too.
            return self.collection.delete_mbox(self.mbox_name)

        d = self.deleteAllDocs()
        d.addCallback(remove_mbox)
        return d

    def _close_cb(self, result):
        self.closed = True

    def close(self):
        """
        Expunge and mark as closed
        """
        d = self.expunge()
        d.addCallback(self._close_cb)
        return d

    def expunge(self):
        """
        Remove all messages flagged \\Deleted
        """
        if not self.isWriteable():
            raise imap4.ReadOnlyMailbox
        d = defer.Deferred()
        # FIXME actually broken.
        # Iterate through index, and do a expunge.
        return d

    # FIXME -- get last_uid from mbox_indexer
    def _bound_seq(self, messages_asked):
        """
        Put an upper bound to a messages sequence if this is open.

        :param messages_asked: IDs of the messages.
        :type messages_asked: MessageSet
        :rtype: MessageSet
        """
        if not messages_asked.last:
            try:
                iter(messages_asked)
            except TypeError:
                # looks like we cannot iterate
                try:
                    messages_asked.last = self.last_uid
                except ValueError:
                    pass
        return messages_asked

    # TODO -- needed? --- we can get the sequence from the indexer.
    def _filter_msg_seq(self, messages_asked):
        """
        Filter a message sequence returning only the ones that do exist in the
        collection.

        :param messages_asked: IDs of the messages.
        :type messages_asked: MessageSet
        :rtype: set
        """
        set_asked = set(messages_asked)
        set_exist = set(self.messages.all_uid_iter())
        seq_messg = set_asked.intersection(set_exist)
        return seq_messg

    def fetch(self, messages_asked, uid):
        """
        Retrieve one or more messages in this mailbox.

        from rfc 3501: The data items to be fetched can be either a single atom
        or a parenthesized list.

        :param messages_asked: IDs of the messages to retrieve information
                               about
        :type messages_asked: MessageSet

        :param uid: If true, the IDs are UIDs. They are message sequence IDs
                    otherwise.
        :type uid: bool

        :rtype: deferred
        """
        # For the moment our UID is sequential, so we
        # can treat them all the same.
        # Change this to the flag that twisted expects when we
        # switch to content-hash based index + local UID table.

        sequence = False
        # sequence = True if uid == 0 else False

        messages_asked = self._bound_seq(messages_asked)
        seq_messg = self._filter_msg_seq(messages_asked)
        getmsg = self.collection.get_msg_by_uid

        # for sequence numbers (uid = 0)
        if sequence:
            logger.debug("Getting msg by index: INEFFICIENT call!")
            # TODO --- implement sequences in mailbox indexer
            raise NotImplementedError
        else:
            got_msg = ((msgid, getmsg(msgid)) for msgid in seq_messg)
            result = ((msgid, msg) for msgid, msg in got_msg
                      if msg is not None)
            reactor.callLater(0, self.unset_recent_flags, seq_messg)

        # TODO -- call signal_to_ui
        # d.addCallback(self.cb_signal_unread_to_ui)

        return result

    def fetch_flags(self, messages_asked, uid):
        """
        A fast method to fetch all flags, tricking just the
        needed subset of the MIME interface that's needed to satisfy
        a generic FLAGS query.

        Given how LEAP Mail is supposed to work without local cache,
        this query is going to be quite common, and also we expect
        it to be in the form 1:* at the beginning of a session, so
        it's not bad to fetch all the FLAGS docs at once.

        :param messages_asked: IDs of the messages to retrieve information
                               about
        :type messages_asked: MessageSet

        :param uid: If 1, the IDs are UIDs. They are message sequence IDs
                    otherwise.
        :type uid: int

        :return: A tuple of two-tuples of message sequence numbers and
                flagsPart, which is a only a partial implementation of
                MessagePart.
        :rtype: tuple
        """
        d = defer.Deferred()
        reactor.callLater(0, self._do_fetch_flags, messages_asked, uid, d)
        if PROFILE_CMD:
            do_profile_cmd(d, "FETCH-ALL-FLAGS")
        return d

    def _do_fetch_flags(self, messages_asked, uid, d):
        """
        :param messages_asked: IDs of the messages to retrieve information
                               about
        :type messages_asked: MessageSet

        :param uid: If 1, the IDs are UIDs. They are message sequence IDs
                    otherwise.
        :type uid: int
        :param d: deferred whose callback will be called with result.
        :type d: Deferred

        :rtype: A tuple of two-tuples of message sequence numbers and
                flagsPart
        """
        class flagsPart(object):
            def __init__(self, uid, flags):
                self.uid = uid
                self.flags = flags

            def getUID(self):
                return self.uid

            def getFlags(self):
                return map(str, self.flags)

        messages_asked = self._bound_seq(messages_asked)
        seq_messg = self._filter_msg_seq(messages_asked)

        # FIXME use deferreds here
        all_flags = self.collection.get_all_flags(self.mbox_name)
        result = ((msgid, flagsPart(
            msgid, all_flags.get(msgid, tuple()))) for msgid in seq_messg)
        d.callback(result)

    def fetch_headers(self, messages_asked, uid):
        """
        A fast method to fetch all headers, tricking just the
        needed subset of the MIME interface that's needed to satisfy
        a generic HEADERS query.

        Given how LEAP Mail is supposed to work without local cache,
        this query is going to be quite common, and also we expect
        it to be in the form 1:* at the beginning of a session, so
        **MAYBE** it's not too bad to fetch all the HEADERS docs at once.

        :param messages_asked: IDs of the messages to retrieve information
                               about
        :type messages_asked: MessageSet

        :param uid: If true, the IDs are UIDs. They are message sequence IDs
                    otherwise.
        :type uid: bool

        :return: A tuple of two-tuples of message sequence numbers and
                headersPart, which is a only a partial implementation of
                MessagePart.
        :rtype: tuple
        """
        # TODO how often is thunderbird doing this?

        class headersPart(object):
            def __init__(self, uid, headers):
                self.uid = uid
                self.headers = headers

            def getUID(self):
                return self.uid

            def getHeaders(self, _):
                return dict(
                    (str(key), str(value))
                    for key, value in
                    self.headers.items())

        messages_asked = self._bound_seq(messages_asked)
        seq_messg = self._filter_msg_seq(messages_asked)

        all_headers = self.messages.all_headers()
        result = ((msgid, headersPart(
            msgid, all_headers.get(msgid, {})))
            for msgid in seq_messg)
        return result

    def cb_signal_unread_to_ui(self, result):
        """
        Sends unread event to ui.
        Used as a callback in several commands.

        :param result: ignored
        """
        d = self._get_unseen_deferred()
        d.addCallback(self.__cb_signal_unread_to_ui)
        return result

    def _get_unseen_deferred(self):
        return self.getUnseenCount()

    def __cb_signal_unread_to_ui(self, unseen):
        """
        Send the unread signal to UI.
        :param unseen: number of unseen messages.
        :type unseen: int
        """
        leap_events.signal(IMAP_UNREAD_MAIL, str(unseen))

    def store(self, messages_asked, flags, mode, uid):
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

        :return: A deferred, that will be called with a dict mapping message
                 sequence numbers to sequences of str representing the flags
                 set on the message after this operation has been performed.
        :rtype: deferred

        :raise ReadOnlyMailbox: Raised if this mailbox is not open for
                                read-write.
        """
        if not self.isWriteable():
            log.msg('read only mailbox!')
            raise imap4.ReadOnlyMailbox

        d = defer.Deferred()
        reactor.callLater(0, self._do_store, messages_asked, flags,
                          mode, uid, d)
        if PROFILE_CMD:
            do_profile_cmd(d, "STORE")
        d.addCallback(self.cb_signal_unread_to_ui)
        d.addErrback(lambda f: log.msg(f.getTraceback()))
        return d

    def _do_store(self, messages_asked, flags, mode, uid, observer):
        """
        Helper method, invoke set_flags method in the IMAPMessageCollection.

        See the documentation for the `store` method for the parameters.

        :param observer: a deferred that will be called with the dictionary
                         mapping UIDs to flags after the operation has been
                         done.
        :type observer: deferred
        """
        # XXX implement also sequence (uid = 0)
        # XXX we should prevent client from setting Recent flag?
        leap_assert(not isinstance(flags, basestring),
                    "flags cannot be a string")
        flags = tuple(flags)
        messages_asked = self._bound_seq(messages_asked)
        seq_messg = self._filter_msg_seq(messages_asked)
        self.collection.set_flags(
            self.mbox_name, seq_messg, flags, mode, observer)

    # ISearchableMailbox

    def search(self, query, uid):
        """
        Search for messages that meet the given query criteria.

        Warning: this is half-baked, and it might give problems since
        it offers the SearchableInterface.
        We'll be implementing it asap.

        :param query: The search criteria
        :type query: list

        :param uid: If true, the IDs specified in the query are UIDs;
                    otherwise they are message sequence IDs.
        :type uid: bool

        :return: A list of message sequence numbers or message UIDs which
                 match the search criteria or a C{Deferred} whose callback
                 will be invoked with such a list.
        :rtype: C{list} or C{Deferred}
        """
        # TODO see if we can raise w/o interrupting flow
        # :raise IllegalQueryError: Raised when query is not valid.
        # example query:
        #  ['UNDELETED', 'HEADER', 'Message-ID',
        #   '52D44F11.9060107@dev.bitmask.net']

        # TODO hardcoding for now! -- we'll support generic queries later on
        # but doing a quickfix for avoiding duplicat saves in the draft folder.
        # See issue #4209

        if len(query) > 2:
            if query[1] == 'HEADER' and query[2].lower() == "message-id":
                msgid = str(query[3]).strip()
                logger.debug("Searching for %s" % (msgid,))
                d = self.messages._get_uid_from_msgid(str(msgid))
                # XXX remove gatherResults
                d1 = defer.gatherResults([d])
                # we want a list, so return it all the same
                return d1

        # nothing implemented for any other query
        logger.warning("Cannot process query: %s" % (query,))
        return []

    # IMessageCopier

    def copy(self, message):
        """
        Copy the given message object into this mailbox.

        :param message: an IMessage implementor
        :type message: LeapMessage
        :return: a deferred that will be fired with the message
                 uid when the copy succeed.
        :rtype: Deferred
        """
        if PROFILE_CMD:
            do_profile_cmd(d, "COPY")

        # A better place for this would be  the COPY/APPEND dispatcher
        # in server.py, but qtreactor hangs when I do that, so this seems
        # to work fine for now.
        #d.addCallback(lambda r: self.reactor.callLater(0, self.notify_new))
        #deferLater(self.reactor, 0, self._do_copy, message, d)
        #return d

        # FIXME not implemented !!! ---
        return self.collection.copy_msg(message, self.mbox_name)

    # convenience fun

    def deleteAllDocs(self):
        """
        Delete all docs in this mailbox
        """
        # FIXME not implemented
        return self.collection.delete_all_docs()

    def unset_recent_flags(self, uid_seq):
        """
        Unset Recent flag for a sequence of UIDs.
        """
        # FIXME not implemented
        return self.collection.unset_recent_flags(uid_seq)

    def __repr__(self):
        """
        Representation string for this mailbox.
        """
        return u"<IMAPMailbox: mbox '%s' (%s)>" % (
            self.mbox_name, self.messages.count())


_INBOX_RE = re.compile(INBOX_NAME, re.IGNORECASE)


def normalize_mailbox(name):
    """
    Return a normalized representation of the mailbox ``name``.

    This method ensures that an eventual initial 'inbox' part of a
    mailbox name is made uppercase.

    :param name: the name of the mailbox
    :type name: unicode

    :rtype: unicode
    """
    # XXX maybe it would make sense to normalize common folders too:
    # trash, sent, drafts, etc...
    if _INBOX_RE.match(name):
        # ensure inital INBOX is uppercase
        return INBOX_NAME + name[len(INBOX_NAME):]
    return name
