# -*- coding: utf-8 -*-
# server.py
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
Soledad-backed IMAP Server.
"""
import copy
import logging
import StringIO
import cStringIO
import time

from collections import defaultdict
from email.parser import Parser

from zope.interface import implements

from twisted.mail import imap4
from twisted.internet import defer
from twisted.python import log

from leap.common import events as leap_events
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL
from leap.common.check import leap_assert, leap_assert_type
from leap.common.mail import get_email_charset
from leap.soledad.client import Soledad

logger = logging.getLogger(__name__)


class MissingIndexError(Exception):
    """
    Raises when tried to access a non existent index document.
    """


class BadIndexError(Exception):
    """
    Raises when index is malformed or has the wrong cardinality.
    """


class WithMsgFields(object):
    """
    Container class for class-attributes to be shared by
    several message-related classes.
    """
    # Internal representation of Message
    DATE_KEY = "date"
    HEADERS_KEY = "headers"
    FLAGS_KEY = "flags"
    MBOX_KEY = "mbox"
    RAW_KEY = "raw"
    SUBJECT_KEY = "subject"
    UID_KEY = "uid"

    # Mailbox specific keys
    CLOSED_KEY = "closed"
    CREATED_KEY = "created"
    SUBSCRIBED_KEY = "subscribed"
    RW_KEY = "rw"

    # Document Type, for indexing
    TYPE_KEY = "type"
    TYPE_MESSAGE_VAL = "msg"
    TYPE_MBOX_VAL = "mbox"

    INBOX_VAL = "inbox"

    # Flags for SoledadDocument for indexing.
    SEEN_KEY = "seen"
    RECENT_KEY = "recent"

    # Flags in Mailbox and Message
    SEEN_FLAG = "\\Seen"
    RECENT_FLAG = "\\Recent"
    ANSWERED_FLAG = "\\Answered"
    FLAGGED_FLAG = "\\Flagged"  # yo dawg
    DELETED_FLAG = "\\Deleted"
    DRAFT_FLAG = "\\Draft"
    NOSELECT_FLAG = "\\Noselect"
    LIST_FLAG = "List"  # is this OK? (no \. ie, no system flag)

    # Fields in mail object
    SUBJECT_FIELD = "Subject"
    DATE_FIELD = "Date"


class IndexedDB(object):
    """
    Methods dealing with the index.

    This is a MixIn that needs access to the soledad instance,
    and also assumes that a INDEXES attribute is accessible to the instance.

    INDEXES must be a dictionary of type:
    {'index-name': ['field1', 'field2']}
    """
    # TODO we might want to move this to soledad itself, check

    def initialize_db(self):
        """
        Initialize the database.
        """
        leap_assert(self._soledad,
                    "Need a soledad attribute accesible in the instance")
        leap_assert_type(self.INDEXES, dict)

        # Ask the database for currently existing indexes.
        if not self._soledad:
            logger.debug("NO SOLEDAD ON IMAP INITIALIZATION")
            return
        db_indexes = dict()
        if self._soledad is not None:
            db_indexes = dict(self._soledad.list_indexes())
        for name, expression in SoledadBackedAccount.INDEXES.items():
            if name not in db_indexes:
                # The index does not yet exist.
                self._soledad.create_index(name, *expression)
                continue

            if expression == db_indexes[name]:
                # The index exists and is up to date.
                continue
            # The index exists but the definition is not what expected, so we
            # delete it and add the proper index expression.
            self._soledad.delete_index(name)
            self._soledad.create_index(name, *expression)


#######################################
# Soledad Account
#######################################


class SoledadBackedAccount(WithMsgFields, IndexedDB):
    """
    An implementation of IAccount and INamespacePresenteer
    that is backed by Soledad Encrypted Documents.
    """

    implements(imap4.IAccount, imap4.INamespacePresenter)

    _soledad = None
    selected = None

    TYPE_IDX = 'by-type'
    TYPE_MBOX_IDX = 'by-type-and-mbox'
    TYPE_MBOX_UID_IDX = 'by-type-and-mbox-and-uid'
    TYPE_SUBS_IDX = 'by-type-and-subscribed'
    TYPE_MBOX_SEEN_IDX = 'by-type-and-mbox-and-seen'
    TYPE_MBOX_RECT_IDX = 'by-type-and-mbox-and-recent'
    TYPE_MBOX_RECT_SEEN_IDX = 'by-type-and-mbox-and-recent-and-seen'

    KTYPE = WithMsgFields.TYPE_KEY
    MBOX_VAL = WithMsgFields.TYPE_MBOX_VAL

    INDEXES = {
        # generic
        TYPE_IDX: [KTYPE],
        TYPE_MBOX_IDX: [KTYPE, MBOX_VAL],
        TYPE_MBOX_UID_IDX: [KTYPE, MBOX_VAL, WithMsgFields.UID_KEY],

        # mailboxes
        TYPE_SUBS_IDX: [KTYPE, 'bool(subscribed)'],

        # messages
        TYPE_MBOX_SEEN_IDX: [KTYPE, MBOX_VAL, 'bool(seen)'],
        TYPE_MBOX_RECT_IDX: [KTYPE, MBOX_VAL, 'bool(recent)'],
        TYPE_MBOX_RECT_SEEN_IDX: [KTYPE, MBOX_VAL,
                                  'bool(recent)', 'bool(seen)'],
    }

    INBOX_NAME = "INBOX"
    MBOX_KEY = MBOX_VAL

    EMPTY_MBOX = {
        WithMsgFields.TYPE_KEY: MBOX_KEY,
        WithMsgFields.TYPE_MBOX_VAL: INBOX_NAME,
        WithMsgFields.SUBJECT_KEY: "",
        WithMsgFields.FLAGS_KEY: [],
        WithMsgFields.CLOSED_KEY: False,
        WithMsgFields.SUBSCRIBED_KEY: False,
        WithMsgFields.RW_KEY: 1,
    }

    def __init__(self, account_name, soledad=None):
        """
        Creates a SoledadAccountIndex that keeps track of the mailboxes
        and subscriptions handled by this account.

        :param acct_name: The name of the account (user id).
        :type acct_name: str

        :param soledad: a Soledad instance.
        :param soledad: Soledad
        """
        leap_assert(soledad, "Need a soledad instance to initialize")
        leap_assert_type(soledad, Soledad)

        # XXX SHOULD assert too that the name matches the user/uuid with which
        # soledad has been initialized.

        self._account_name = account_name.upper()
        self._soledad = soledad

        self.initialize_db()

        # every user should have the right to an inbox folder
        # at least, so let's make one!

        if not self.mailboxes:
            self.addMailbox(self.INBOX_NAME)

    def _get_empty_mailbox(self):
        """
        Returns an empty mailbox.

        :rtype: dict
        """
        return copy.deepcopy(self.EMPTY_MBOX)

    def _get_mailbox_by_name(self, name):
        """
        Returns an mbox document by name.

        :param name: the name of the mailbox
        :type name: str

        :rtype: SoledadDocument
        """
        # XXX only upper for INBOX ---
        name = name.upper()
        doc = self._soledad.get_from_index(
            self.TYPE_MBOX_IDX, self.MBOX_KEY, name)
        return doc[0] if doc else None

    @property
    def mailboxes(self):
        """
        A list of the current mailboxes for this account.
        """
        return [str(doc.content[self.MBOX_KEY])
                for doc in self._soledad.get_from_index(
                    self.TYPE_IDX, self.MBOX_KEY)]

    @property
    def subscriptions(self):
        """
        A list of the current subscriptions for this account.
        """
        return [str(doc.content[self.MBOX_KEY])
                for doc in self._soledad.get_from_index(
                    self.TYPE_SUBS_IDX, self.MBOX_KEY, '1')]

    def getMailbox(self, name):
        """
        Returns a Mailbox with that name, without selecting it.

        :param name: name of the mailbox
        :type name: str

        :returns: a a SoledadMailbox instance
        :rtype: SoledadMailbox
        """
        # XXX only upper for INBOX
        name = name.upper()
        if name not in self.mailboxes:
            raise imap4.MailboxException("No such mailbox")

        return SoledadMailbox(name, soledad=self._soledad)

    ##
    ## IAccount
    ##

    def addMailbox(self, name, creation_ts=None):
        """
        Adds a mailbox to the account.

        :param name: the name of the mailbox
        :type name: str

        :param creation_ts: a optional creation timestamp to be used as
                            mailbox id. A timestamp will be used if no
                            one is provided.
        :type creation_ts: int

        :returns: True if successful
        :rtype: bool
        """
        # XXX only upper for INBOX
        name = name.upper()
        # XXX should check mailbox name for RFC-compliant form

        if name in self.mailboxes:
            raise imap4.MailboxCollision, name

        if not creation_ts:
            # by default, we pass an int value
            # taken from the current time
            # we make sure to take enough decimals to get a unique
            # maibox-uidvalidity.
            creation_ts = int(time.time() * 10E2)

        mbox = self._get_empty_mailbox()
        mbox[self.MBOX_KEY] = name
        mbox[self.CREATED_KEY] = creation_ts

        doc = self._soledad.create_doc(mbox)
        return bool(doc)

    def create(self, pathspec):
        """
        Create a new mailbox from the given hierarchical name.

        :param pathspec: The full hierarchical name of a new mailbox to create.
                         If any of the inferior hierarchical names to this one
                         do not exist, they are created as well.
        :type pathspec: str

        :return: A true value if the creation succeeds.
        :rtype: bool

        :raise MailboxException: Raised if this mailbox cannot be added.
        """
        # TODO raise MailboxException

        paths = filter(None, pathspec.split('/'))
        for accum in range(1, len(paths)):
            try:
                self.addMailbox('/'.join(paths[:accum]))
            except imap4.MailboxCollision:
                pass
        try:
            self.addMailbox('/'.join(paths))
        except imap4.MailboxCollision:
            if not pathspec.endswith('/'):
                return False
        return True

    def select(self, name, readwrite=1):
        """
        Selects a mailbox.

        :param name: the mailbox to select
        :type name: str

        :param readwrite: 1 for readwrite permissions.
        :type readwrite: int

        :rtype: bool
        """
        # XXX only upper for INBOX
        name = name.upper()

        if name not in self.mailboxes:
            return None

        self.selected = str(name)

        return SoledadMailbox(
            name, rw=readwrite,
            soledad=self._soledad)

    def delete(self, name, force=False):
        """
        Deletes a mailbox.

        Right now it does not purge the messages, but just removes the mailbox
        name from the mailboxes list!!!

        :param name: the mailbox to be deleted
        :type name: str

        :param force: if True, it will not check for noselect flag or inferior
                      names. use with care.
        :type force: bool
        """
        # XXX only upper for INBOX
        name = name.upper()
        if not name in self.mailboxes:
            raise imap4.MailboxException("No such mailbox")

        mbox = self.getMailbox(name)

        if force is False:
            # See if this box is flagged \Noselect
            # XXX use mbox.flags instead?
            if self.NOSELECT_FLAG in mbox.getFlags():
                # Check for hierarchically inferior mailboxes with this one
                # as part of their root.
                for others in self.mailboxes:
                    if others != name and others.startswith(name):
                        raise imap4.MailboxException, (
                            "Hierarchically inferior mailboxes "
                            "exist and \\Noselect is set")
        mbox.destroy()

        # XXX FIXME --- not honoring the inferior names...

        # if there are no hierarchically inferior names, we will
        # delete it from our ken.
        #if self._inferiorNames(name) > 1:
            # ??! -- can this be rite?
            #self._index.removeMailbox(name)

    def rename(self, oldname, newname):
        """
        Renames a mailbox.

        :param oldname: old name of the mailbox
        :type oldname: str

        :param newname: new name of the mailbox
        :type newname: str
        """
        # XXX only upper for INBOX
        oldname = oldname.upper()
        newname = newname.upper()

        if oldname not in self.mailboxes:
            raise imap4.NoSuchMailbox, oldname

        inferiors = self._inferiorNames(oldname)
        inferiors = [(o, o.replace(oldname, newname, 1)) for o in inferiors]

        for (old, new) in inferiors:
            if new in self.mailboxes:
                raise imap4.MailboxCollision, new

        for (old, new) in inferiors:
            mbox = self._get_mailbox_by_name(old)
            mbox.content[self.MBOX_KEY] = new
            self._soledad.put_doc(mbox)

        # XXX ---- FIXME!!!! ------------------------------------
        # until here we just renamed the index...
        # We have to rename also the occurrence of this
        # mailbox on ALL the messages that are contained in it!!!
        # ... we maybe could use a reference to the doc_id
        # in each msg, instead of the "mbox" field in msgs
        # -------------------------------------------------------

    def _inferiorNames(self, name):
        """
        Return hierarchically inferior mailboxes.

        :param name: name of the mailbox
        :rtype: list
        """
        # XXX use wildcard query instead
        inferiors = []
        for infname in self.mailboxes:
            if infname.startswith(name):
                inferiors.append(infname)
        return inferiors

    def isSubscribed(self, name):
        """
        Returns True if user is subscribed to this mailbox.

        :param name: the mailbox to be checked.
        :type name: str

        :rtype: bool
        """
        mbox = self._get_mailbox_by_name(name)
        return mbox.content.get('subscribed', False)

    def _set_subscription(self, name, value):
        """
        Sets the subscription value for a given mailbox

        :param name: the mailbox
        :type name: str

        :param value: the boolean value
        :type value: bool
        """
        # maybe we should store subscriptions in another
        # document...
        if not name in self.mailboxes:
            self.addMailbox(name)
        mbox = self._get_mailbox_by_name(name)

        if mbox:
            mbox.content[self.SUBSCRIBED_KEY] = value
            self._soledad.put_doc(mbox)

    def subscribe(self, name):
        """
        Subscribe to this mailbox

        :param name: name of the mailbox
        :type name: str
        """
        name = name.upper()
        if name not in self.subscriptions:
            self._set_subscription(name, True)

    def unsubscribe(self, name):
        """
        Unsubscribe from this mailbox

        :param name: name of the mailbox
        :type name: str
        """
        name = name.upper()
        if name not in self.subscriptions:
            raise imap4.MailboxException, "Not currently subscribed to " + name
        self._set_subscription(name, False)

    def listMailboxes(self, ref, wildcard):
        """
        List the mailboxes.

        from rfc 3501:
        returns a subset of names from the complete set
        of all names available to the client.  Zero or more untagged LIST
        replies are returned, containing the name attributes, hierarchy
        delimiter, and name.

        :param ref: reference name
        :type ref: str

        :param wildcard: mailbox name with possible wildcards
        :type wildcard: str
        """
        # XXX use wildcard in index query
        ref = self._inferiorNames(ref.upper())
        wildcard = imap4.wildcardToRegexp(wildcard, '/')
        return [(i, self.getMailbox(i)) for i in ref if wildcard.match(i)]

    ##
    ## INamespacePresenter
    ##

    def getPersonalNamespaces(self):
        return [["", "/"]]

    def getSharedNamespaces(self):
        return None

    def getOtherNamespaces(self):
        return None

    # extra, for convenience

    def deleteAllMessages(self, iknowhatiamdoing=False):
        """
        Deletes all messages from all mailboxes.
        Danger! high voltage!

        :param iknowhatiamdoing: confirmation parameter, needs to be True
                                 to proceed.
        """
        if iknowhatiamdoing is True:
            for mbox in self.mailboxes:
                self.delete(mbox, force=True)

    def __repr__(self):
        """
        Representation string for this object.
        """
        return "<SoledadBackedAccount (%s)>" % self._account_name

#######################################
# LeapMessage, MessageCollection
# and Mailbox
#######################################


class LeapMessage(WithMsgFields):

    implements(imap4.IMessage, imap4.IMessageFile)

    def __init__(self, doc):
        """
        Initializes a LeapMessage.

        :param doc: A SoledadDocument containing the internal
                    representation of the message
        :type doc: SoledadDocument
        """
        self._doc = doc

    def getUID(self):
        """
        Retrieve the unique identifier associated with this message

        :return: uid for this message
        :rtype: int
        """
        # XXX debug, to remove after a while...
        if not self._doc:
            log.msg('BUG!!! ---- message has no doc!')
            return
        return self._doc.content[self.UID_KEY]

    def getFlags(self):
        """
        Retrieve the flags associated with this message

        :return: The flags, represented as strings
        :rtype: iterable
        """
        if self._doc is None:
            return []
        flags = self._doc.content.get(self.FLAGS_KEY, None)
        if flags:
            flags = map(str, flags)
        return flags

    # setFlags, addFlags, removeFlags are not in the interface spec
    # but we use them with store command.

    def setFlags(self, flags):
        """
        Sets the flags for this message

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to update in the message.
        :type flags: sequence of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        log.msg('setting flags')
        doc = self._doc
        doc.content[self.FLAGS_KEY] = flags
        doc.content[self.SEEN_KEY] = self.SEEN_FLAG in flags
        doc.content[self.RECENT_KEY] = self.RECENT_FLAG in flags
        return doc

    def addFlags(self, flags):
        """
        Adds flags to this message.

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to add to the message.
        :type flags: sequence of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        oldflags = self.getFlags()
        return self.setFlags(list(set(flags + oldflags)))

    def removeFlags(self, flags):
        """
        Remove flags from this message.

        Returns a SoledadDocument that needs to be updated by the caller.

        :param flags: the flags to be removed from the message.
        :type flags: sequence of str

        :return: a SoledadDocument instance
        :rtype: SoledadDocument
        """
        oldflags = self.getFlags()
        return self.setFlags(list(set(oldflags) - set(flags)))

    def getInternalDate(self):
        """
        Retrieve the date internally associated with this message

        @rtype: C{str}
        @retur: An RFC822-formatted date string.
        """
        return str(self._doc.content.get(self.DATE_KEY, ''))

    #
    # IMessageFile
    #

    """
    Optional message interface for representing messages as files.

    If provided by message objects, this interface will be used instead
    the more complex MIME-based interface.
    """

    def open(self):
        """
        Return an file-like object opened for reading.

        Reading from the returned file will return all the bytes
        of which this message consists.

        :return: file-like object opened fore reading.
        :rtype: StringIO
        """
        fd = cStringIO.StringIO()
        charset = get_email_charset(self._doc.content.get(self.RAW_KEY, ''))
        content = self._doc.content.get(self.RAW_KEY, '')
        try:
            content = content.encode(charset)
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            logger.error("Unicode error {0}".format(e))
            content = content.encode(charset, 'replace')
        fd.write(content)
        fd.seek(0)
        return fd

    #
    # IMessagePart
    #

    # XXX should implement the rest of IMessagePart interface:
    # (and do not use the open above)

    def getBodyFile(self):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: StringIO
        """
        fd = StringIO.StringIO()
        charset = get_email_charset(self._doc.content.get(self.RAW_KEY, ''))
        content = self._doc.content.get(self.RAW_KEY, '')
        try:
            content = content.encode(charset)
        except (UnicodeEncodeError, UnicodeDecodeError) as e:
            logger.error("Unicode error {0}".format(e))
            content = content.encode(charset, 'replace')
        fd.write(content)
        # SHOULD use a separate BODY FIELD ...
        fd.seek(0)
        return fd

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        return self.getBodyFile().len

    def _get_headers(self):
        """
        Return the headers dict stored in this message document.
        """
        return self._doc.content.get(self.HEADERS_KEY, {})

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
        headers = self._get_headers()
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
        return dict(filter_by_cond)

    # --- no multipart for now
    # XXX Fix MULTIPART SUPPORT!

    def isMultipart(self):
        return False

    def getSubPart(part):
        return None

    #
    # accessors
    #

    def __getitem__(self, key):
        """
        Return the content of the message document.

        @param key: The key
        @type key: str

        @return: The content value indexed by C{key} or None
        @rtype: str
        """
        return self._doc.content.get(key, None)


class MessageCollection(WithMsgFields, IndexedDB):
    """
    A collection of messages, surprisingly.

    It is tied to a selected mailbox name that is passed to constructor.
    Implements a filter query over the messages contained in a soledad
    database.
    """
    # XXX this should be able to produce a MessageSet methinks

    EMPTY_MSG = {
        WithMsgFields.TYPE_KEY: WithMsgFields.TYPE_MESSAGE_VAL,
        WithMsgFields.UID_KEY: 1,
        WithMsgFields.MBOX_KEY: WithMsgFields.INBOX_VAL,
        WithMsgFields.SUBJECT_KEY: "",
        WithMsgFields.DATE_KEY: "",
        WithMsgFields.SEEN_KEY: False,
        WithMsgFields.RECENT_KEY: True,
        WithMsgFields.FLAGS_KEY: [],
        WithMsgFields.HEADERS_KEY: {},
        WithMsgFields.RAW_KEY: "",
    }

    # get from SoledadBackedAccount the needed index-related constants
    INDEXES = SoledadBackedAccount.INDEXES
    TYPE_IDX = SoledadBackedAccount.TYPE_IDX

    def __init__(self, mbox=None, soledad=None):
        """
        Constructor for MessageCollection.

        :param mbox: the name of the mailbox. It is the name
                     with which we filter the query over the
                     messages database
        :type mbox: str

        :param soledad: Soledad database
        :type soledad: Soledad instance
        """
        # XXX pass soledad directly

        leap_assert(mbox, "Need a mailbox name to initialize")
        leap_assert(mbox.strip() != "", "mbox cannot be blank space")
        leap_assert(isinstance(mbox, (str, unicode)),
                    "mbox needs to be a string")
        leap_assert(soledad, "Need a soledad instance to initialize")

        # This is a wrapper now!...
        # should move assertion there...
        #leap_assert(isinstance(soledad._db, SQLCipherDatabase),
                    #"soledad._db must be an instance of SQLCipherDatabase")

        # okay, all in order, keep going...

        self.mbox = mbox.upper()
        self._soledad = soledad
        self.initialize_db()
        self._parser = Parser()

    def _get_empty_msg(self):
        """
        Returns an empty message.

        :return: a dict containing a default empty message
        :rtype: dict
        """
        return copy.deepcopy(self.EMPTY_MSG)

    def add_msg(self, raw, subject=None, flags=None, date=None, uid=1):
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

        :param uid: the message uid for this mailbox
        :type uid: int
        """
        if flags is None:
            flags = tuple()
        leap_assert_type(flags, tuple)

        def stringify(o):
            if isinstance(o, (cStringIO.OutputType, StringIO.StringIO)):
                return o.getvalue()
            else:
                return o

        content = self._get_empty_msg()
        content[self.MBOX_KEY] = self.mbox

        if flags:
            content[self.FLAGS_KEY] = map(stringify, flags)
            content[self.SEEN_KEY] = self.SEEN_FLAG in flags

        def _get_parser_fun(o):
            if isinstance(o, (cStringIO.OutputType, StringIO.StringIO)):
                return self._parser.parse
            if isinstance(o, (str, unicode)):
                return self._parser.parsestr

        msg = _get_parser_fun(raw)(raw, True)
        headers = dict(msg)

        # XXX get lower case for keys?
        content[self.HEADERS_KEY] = headers
        # set subject based on message headers and eventually replace by
        # subject given as param
        if self.SUBJECT_FIELD in headers:
            content[self.SUBJECT_KEY] = headers[self.SUBJECT_FIELD]
        if subject is not None:
            content[self.SUBJECT_KEY] = subject
        content[self.RAW_KEY] = stringify(raw)

        if not date and self.DATE_FIELD in headers:
            content[self.DATE_KEY] = headers[self.DATE_FIELD]
        else:
            content[self.DATE_KEY] = date

        # ...should get a sanity check here.
        content[self.UID_KEY] = uid

        return self._soledad.create_doc(content)

    def remove(self, msg):
        """
        Removes a message.

        :param msg: a u1db doc containing the message
        :type msg: SoledadDocument
        """
        self._soledad.delete_doc(msg)

    # getters

    def get_by_uid(self, uid):
        """
        Retrieves a message document by UID.

        :param uid: the message uid to query by
        :type uid: int

        :return: A SoledadDocument instance matching the query,
                 or None if not found.
        :rtype: SoledadDocument
        """
        docs = self._soledad.get_from_index(
            SoledadBackedAccount.TYPE_MBOX_UID_IDX,
            self.TYPE_MESSAGE_VAL, self.mbox, str(uid))

        return docs[0] if docs else None

    def get_msg_by_uid(self, uid):
        """
        Retrieves a LeapMessage by UID.

        :param uid: the message uid to query by
        :type uid: int

        :return: A LeapMessage instance matching the query,
                 or None if not found.
        :rtype: LeapMessage
        """
        doc = self.get_by_uid(uid)
        if doc:
            return LeapMessage(doc)

    def get_by_index(self, index):
        """
        Retrieves a mesage document by mailbox index.

        :param index: the index of the sequence (zero-indexed)
        :type index: int
        """
        try:
            return self.get_all()[index]
        except IndexError:
            return None

    def get_msg_by_index(self, index):
        """
        Retrieves a LeapMessage by sequence index.

        :param index: the index of the sequence (zero-indexed)
        :type index: int
        """
        doc = self.get_by_index(index)
        if doc:
            return LeapMessage(doc)

    def is_deleted(self, doc):
        """
        Returns whether a given doc is deleted or not.

        :param doc: the document to check
        :rtype: bool
        """
        return self.DELETED_FLAG in doc.content[self.FLAGS_KEY]

    def get_last(self):
        """
        Gets the last LeapMessage
        """
        _all = self.get_all()
        if not _all:
            return None
        return LeapMessage(_all[-1])

    def get_all(self):
        """
        Get all message documents for the selected mailbox.
        If you want acess to the content, use __iter__ instead

        :return: a list of u1db documents
        :rtype: list of SoledadDocument
        """
        # XXX this should return LeapMessage instances
        all_docs = [doc for doc in self._soledad.get_from_index(
            SoledadBackedAccount.TYPE_MBOX_IDX,
            self.TYPE_MESSAGE_VAL, self.mbox)]
            #if not self.is_deleted(doc)]
        # highly inneficient, but first let's grok it and then
        # let's worry about efficiency.
        return sorted(all_docs, key=lambda item: item.content['uid'])

    def unseen_iter(self):
        """
        Get an iterator for the message docs with no `seen` flag

        :return: iterator through unseen message docs
        :rtype: iterable
        """
        return (doc for doc in
                self._soledad.get_from_index(
                    SoledadBackedAccount.TYPE_MBOX_RECT_SEEN_IDX,
                    self.TYPE_MESSAGE_VAL, self.mbox, '1', '0'))

    def get_unseen(self):
        """
        Get all messages with the `Unseen` flag

        :returns: a list of LeapMessages
        :rtype: list
        """
        return [LeapMessage(doc) for doc in self.unseen_iter()]

    def recent_iter(self):
        """
        Get an iterator for the message docs with `recent` flag.

        :return: iterator through recent message docs
        :rtype: iterable
        """
        return (doc for doc in
                self._soledad.get_from_index(
                    SoledadBackedAccount.TYPE_MBOX_RECT_IDX,
                    self.TYPE_MESSAGE_VAL, self.mbox, '1'))

    def get_recent(self):
        """
        Get all messages with the `Recent` flag.

        :returns: a list of LeapMessages
        :rtype: list
        """
        return [LeapMessage(doc) for doc in self.recent_iter()]

    def count(self):
        """
        Return the count of messages for this mailbox.

        :rtype: int
        """
        return len(self.get_all())

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
        # XXX return LeapMessage instead?! (change accordingly)
        return (m.content for m in self.get_all())

    def __getitem__(self, uid):
        """
        Allows indexing as a list, with msg uid as the index.

        :param uid: an integer index
        :type uid: int

        :return: LeapMessage or None if not found.
        :rtype: LeapMessage
        """
        #try:
            #return self.get_msg_by_uid(uid)
        try:
            return [doc
                    for doc in self.get_all()][uid - 1]
        except IndexError:
            return None

    def __repr__(self):
        """
        Representation string for this object.
        """
        return u"<MessageCollection: mbox '%s' (%s)>" % (
            self.mbox, self.count())

    # XXX should implement __eq__ also


class SoledadMailbox(WithMsgFields):
    """
    A Soledad-backed IMAP mailbox.

    Implements the high-level method needed for the Mailbox interfaces.
    The low-level database methods are contained in MessageCollection class,
    which we instantiate and make accessible in the `messages` attribute.
    """
    implements(imap4.IMailboxInfo, imap4.IMailbox, imap4.ICloseableMailbox)
    # XXX should finish the implementation of IMailboxListener

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

        self.mbox = mbox
        self.rw = rw

        self._soledad = soledad

        self.messages = MessageCollection(
            mbox=mbox, soledad=soledad)

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
        Rdds a listener to the listeners queue.

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
                SoledadBackedAccount.TYPE_MBOX_IDX,
                self.TYPE_MBOX_VAL, self.mbox)
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
        #return map(str, self.INIT_FLAGS)

        # XXX CHECK against thunderbird XXX
        # XXX I think this is slightly broken.. :/

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
        # TODO -- fix also getFlags
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
        mailbox. Currently it returns the current length incremented
        by one.

        :rtype: int
        """
        last = self.messages.get_last()
        if last:
            nextuid = last.getUID() + 1
        else:
            nextuid = 1
        return nextuid

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
        return len(self.messages.get_unseen())

    def getRecentCount(self):
        """
        Returns the number of messages with the 'Recent' flag.

        :return: count of messages flagged `recent`
        :rtype: int
        """
        return len(self.messages.get_recent())

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
            r[self.CMD_UIDNEXT] = self.getMessageCount() + 1
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
        # XXX we should treat the message as an IMessage from here
        uid_next = self.getUIDNext()
        flags = tuple(str(flag) for flag in flags)

        self.messages.add_msg(message, flags=flags, date=date,
                              uid=uid_next)

        # XXX recent should not include deleted...??
        exists = len(self.messages)
        recent = len(self.messages.get_recent())
        for listener in self.listeners:
            listener.newMessages(exists, recent)
        return defer.succeed(None)

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

    def expunge(self):
        """
        Remove all messages flagged \\Deleted
        """
        if not self.isWriteable():
            raise imap4.ReadOnlyMailbox

        delete = []
        deleted = []
        for m in self.messages.get_all():
            if self.DELETED_FLAG in m.content[self.FLAGS_KEY]:
                delete.append(m)
        for m in delete:
            deleted.append(m.content)
            self.messages.remove(m)

        # XXX should return the UIDs of the deleted messages
        # more generically
        return [x for x in range(len(deleted))]

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
                last = self.messages.get_last()
                uid_last = last.getUID()
                messages.last = uid_last

        # for sequence numbers (uid = 0)
        if sequence:
            for msg_id in messages:
                msg = self.messages.get_msg_by_index(msg_id - 1)
                if msg:
                    result.append((msg.getUID(), msg))
                else:
                    print "fetch %s, no msg found!!!" % msg_id

        else:
            for msg_id in messages:
                msg = self.messages.get_msg_by_uid(msg_id)
                if msg:
                    result.append((msg_id, msg))
                else:
                    print "fetch %s, no msg found!!!" % msg_id

        return tuple(result)

    def _signal_unread_to_ui(self):
        """
        Sends unread event to ui.
        """
        leap_events.signal(
            IMAP_UNREAD_MAIL, str(self.getUnseenCount()))

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

        if not self.isWriteable():
            log.msg('read only mailbox!')
            raise imap4.ReadOnlyMailbox

        if not messages.last:
            messages.last = self.messages.count()

        result = {}
        for msg_id in messages:
            print "MSG ID = %s" % msg_id
            msg = self.messages.get_msg_by_uid(msg_id)
            if mode == 1:
                self._update(msg.addFlags(flags))
            elif mode == -1:
                self._update(msg.removeFlags(flags))
            elif mode == 0:
                self._update(msg.setFlags(flags))
            result[msg_id] = msg.getFlags()

        self._signal_unread_to_ui()
        return result

    def close(self):
        """
        Expunge and mark as closed
        """
        self.expunge()
        self.closed = True

    # convenience fun

    def deleteAllDocs(self):
        """
        Deletes all docs in this mailbox
        """
        docs = self.messages.get_all()
        for doc in docs:
            self.messages._soledad.delete_doc(doc)

    def _update(self, doc):
        """
        Updates document in u1db database
        """
        #log.msg('updating doc... %s ' % doc)
        self._soledad.put_doc(doc)

    def __repr__(self):
        """
        Representation string for this mailbox.
        """
        return u"<SoledadMailbox: mbox '%s' (%s)>" % (
            self.mbox, self.messages.count())
