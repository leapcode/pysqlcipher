import copy

from zope.interface import implements

from twisted.mail import imap4
from twisted.internet import defer

#from twisted import cred

import u1db


# TODO delete this SimpleMailbox
class SimpleMailbox:
    """
    A simple Mailbox for reference
    We don't intend to use this, only for debugging purposes
    until we stabilize unittests with SoledadMailbox
    """
    implements(imap4.IMailboxInfo, imap4.IMailbox, imap4.ICloseableMailbox)

    flags = ('\\Flag1', 'Flag2', '\\AnotherSysFlag', 'LastFlag')
    messages = []
    mUID = 0
    rw = 1
    closed = False

    def __init__(self):
        self.listeners = []
        self.addListener = self.listeners.append
        self.removeListener = self.listeners.remove

    def getFlags(self):
        return self.flags

    def getUIDValidity(self):
        return 42

    def getUIDNext(self):
        return len(self.messages) + 1

    def getMessageCount(self):
        return 9

    def getRecentCount(self):
        return 3

    def getUnseenCount(self):
        return 4

    def isWriteable(self):
        return self.rw

    def destroy(self):
        pass

    def getHierarchicalDelimiter(self):
        return '/'

    def requestStatus(self, names):
        r = {}
        if 'MESSAGES' in names:
            r['MESSAGES'] = self.getMessageCount()
        if 'RECENT' in names:
            r['RECENT'] = self.getRecentCount()
        if 'UIDNEXT' in names:
            r['UIDNEXT'] = self.getMessageCount() + 1
        if 'UIDVALIDITY' in names:
            r['UIDVALIDITY'] = self.getUID()
        if 'UNSEEN' in names:
            r['UNSEEN'] = self.getUnseenCount()
        return defer.succeed(r)

    def addMessage(self, message, flags, date=None):
        self.messages.append((message, flags, date, self.mUID))
        self.mUID += 1
        return defer.succeed(None)

    def expunge(self):
        delete = []
        for i in self.messages:
            if '\\Deleted' in i[1]:
                delete.append(i)
        for i in delete:
            self.messages.remove(i)
        return [i[3] for i in delete]

    def close(self):
        self.closed = True


###################################
# SoledadAccount Index
###################################

class MissingIndexError(Exception):
    """raises when tried to access a non existent index document"""


class BadIndexError(Exception):
    """raises when index is malformed or has the wrong cardinality"""


EMPTY_INDEXDOC = {"is_index": True, "mailboxes": [], "subscriptions": []}
get_empty_indexdoc = lambda: copy.deepcopy(EMPTY_INDEXDOC)


class SoledadAccountIndex(object):
    """
    Index for the Soledad Account
    keeps track of mailboxes and subscriptions
    """
    _index = None

    def __init__(self, soledad=None):
        self._soledad = soledad
        self._db = soledad._db
        self._initialize_db()

    def _initialize_db(self):
        """initialize the database"""
        db_indexes = dict(self._soledad._db.list_indexes())
        name, expression = "isindex", ["bool(is_index)"]
        if name not in db_indexes:
            self._soledad._db.create_index(name, *expression)
        try:
            self._index = self._get_index_doc()
        except MissingIndexError:
            print "no index!!! creating..."
            self._create_index_doc()

    def _create_index_doc(self):
        """creates an empty index document"""
        indexdoc = get_empty_indexdoc()
        self._index = self._soledad.create_doc(
            indexdoc)

    def _get_index_doc(self):
        """gets index document"""
        indexdoc = self._db.get_from_index("isindex", "*")
        if not indexdoc:
            raise MissingIndexError
        if len(indexdoc) > 1:
            raise BadIndexError
        return indexdoc[0]

    def _update_index_doc(self):
        """updates index document"""
        self._db.put_doc(self._index)

    # setters and getters for the index document

    def _get_mailboxes(self):
        """Get mailboxes associated with this account."""
        return self._index.content.setdefault('mailboxes', [])

    def _set_mailboxes(self, mailboxes):
        """Set mailboxes associated with this account."""
        self._index.content['mailboxes'] = list(set(mailboxes))
        self._update_index_doc()

    mailboxes = property(
        _get_mailboxes, _set_mailboxes, doc="Account mailboxes.")

    def _get_subscriptions(self):
        """Get subscriptions associated with this account."""
        return self._index.content.setdefault('subscriptions', [])

    def _set_subscriptions(self, subscriptions):
        """Set subscriptions associated with this account."""
        self._index.content['subscriptions'] = list(set(subscriptions))
        self._update_index_doc()

    subscriptions = property(
        _get_subscriptions, _set_subscriptions, doc="Account subscriptions.")

    def addMailbox(self, name):
        """add a mailbox to the mailboxes list."""
        name = name.upper()
        self.mailboxes.append(name)
        self._update_index_doc()

    def removeMailbox(self, name):
        """remove a mailbox from the mailboxes list."""
        self.mailboxes.remove(name)
        self._update_index_doc()

    def addSubscription(self, name):
        """add a subscription to the subscriptions list."""
        name = name.upper()
        self.subscriptions.append(name)
        self._update_index_doc()

    def removeSubscription(self, name):
        """remove a subscription from the subscriptions list."""
        self.subscriptions.remove(name)
        self._update_index_doc()


#######################################
# Soledad Account
#######################################

class SoledadBackedAccount(object):

    implements(imap4.IAccount, imap4.INamespacePresenter)

    #mailboxes = None
    #subscriptions = None

    top_id = 0  # XXX move top_id to _index
    _soledad = None
    _db = None

    def __init__(self, name, soledad=None):
        self.name = name
        self._soledad = soledad
        self._db = soledad._db
        self._index = SoledadAccountIndex(soledad=soledad)

        #self.mailboxes = {}
        #self.subscriptions = []

    def allocateID(self):
        id = self.top_id  # XXX move to index !!!
        self.top_id += 1
        return id

    @property
    def mailboxes(self):
        return self._index.mailboxes

    @property
    def subscriptions(self):
        return self._index.subscriptions

    ##
    ## IAccount
    ##

    def addMailbox(self, name, mbox=None):
        name = name.upper()
        if name in self.mailboxes:
            raise imap4.MailboxCollision, name
        if mbox is None:
            mbox = self._emptyMailbox(name, self.allocateID())
        self._index.addMailbox(name)
        return 1

    def create(self, pathspec):
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

    def _emptyMailbox(self, name, id):
        # XXX implement!!!
        raise NotImplementedError

    def select(self, name, readwrite=1):
        return self.mailboxes.get(name.upper())

    def delete(self, name):
        name = name.upper()
        # See if this mailbox exists at all
        mbox = self.mailboxes.get(name)
        if not mbox:
            raise imap4.MailboxException("No such mailbox")
        # See if this box is flagged \Noselect
        if r'\Noselect' in mbox.getFlags():
            # Check for hierarchically inferior mailboxes with this one
            # as part of their root.
            for others in self.mailboxes.keys():
                if others != name and others.startswith(name):
                    raise imap4.MailboxException, (
                        "Hierarchically inferior mailboxes "
                        "exist and \\Noselect is set")
        mbox.destroy()

        # iff there are no hierarchically inferior names, we will
        # delete it from our ken.
        if self._inferiorNames(name) > 1:
            del self.mailboxes[name]

    def rename(self, oldname, newname):
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
            self.mailboxes[new] = self.mailboxes[old]
            del self.mailboxes[old]

    def _inferiorNames(self, name):
        inferiors = []
        for infname in self.mailboxes.keys():
            if infname.startswith(name):
                inferiors.append(infname)
        return inferiors

    def isSubscribed(self, name):
        return name.upper() in self.subscriptions

    def subscribe(self, name):
        name = name.upper()
        if name not in self.subscriptions:
            self._index.addSubscription(name)

    def unsubscribe(self, name):
        name = name.upper()
        if name not in self.subscriptions:
            raise imap4.MailboxException, "Not currently subscribed to " + name
        self._index.removeSubscription(name)

    def listMailboxes(self, ref, wildcard):
        ref = self._inferiorNames(ref.upper())
        wildcard = imap4.wildcardToRegexp(wildcard, '/')
        return [(i, self.mailboxes[i]) for i in ref if wildcard.match(i)]

    ##
    ## INamespacePresenter
    ##

    def getPersonalNamespaces(self):
        return [["", "/"]]

    def getSharedNamespaces(self):
        return None

    def getOtherNamespaces(self):
        return None

#######################################
# Soledad Message, MessageCollection
# and Mailbox
#######################################

FLAGS_INDEX = 'flags'
SEEN_INDEX = 'seen'
INDEXES = {FLAGS_INDEX: ['flags'],
           SEEN_INDEX: ['bool(seen)'],
}


class Message(u1db.Document):
    """A rfc822 message item."""
    # XXX TODO use email module

    def _get_subject(self):
        """Get the message title."""
        return self.content.get('subject')

    def _set_subject(self, subject):
        """Set the message title."""
        self.content['subject'] = subject

    subject = property(_get_subject, _set_subject,
                       doc="Subject of the message.")

    def _get_seen(self):
        """Get the seen status of the message."""
        return self.content.get('seen', False)

    def _set_seen(self, value):
        """Set the seen status."""
        self.content['seen'] = value

    seen = property(_get_seen, _set_seen, doc="Seen flag.")

    def _get_flags(self):
        """Get flags associated with the message."""
        return self.content.setdefault('flags', [])

    def _set_flags(self, flags):
        """Set flags associated with the message."""
        self.content['flags'] = list(set(flags))

    flags = property(_get_flags, _set_flags, doc="Message flags.")

EMPTY_MSG = {
    "subject": "",
    "seen": False,
    "flags": [],
    "mailbox": "",
}
get_empty_msg = lambda: copy.deepcopy(EMPTY_MSG)


class MessageCollection(object):
    """
    A collection of messages
    """

    def __init__(self, mbox=None, db=None):
        assert mbox
        self.db = db
        self.initialize_db()

    def initialize_db(self):
        """Initialize the database."""
        # Ask the database for currently existing indexes.
        db_indexes = dict(self.db.list_indexes())
        # Loop through the indexes we expect to find.
        for name, expression in INDEXES.items():
            print 'name is', name
            if name not in db_indexes:
                # The index does not yet exist.
                print 'creating index'
                self.db.create_index(name, *expression)
                continue

            if expression == db_indexes[name]:
                print 'expression up to date'
                # The index exists and is up to date.
                continue
            # The index exists but the definition is not what expected, so we
            # delete it and add the proper index expression.
            print 'deleting index'
            self.db.delete_index(name)
            self.db.create_index(name, *expression)

    def add_msg(self, subject=None, flags=None):
        """Create a new message document."""
        if flags is None:
            flags = []
        content = get_empty_msg()
        if subject or flags:
            content['subject'] = subject
            content['flags'] = flags
        # Store the document in the database. Since we did not set a document
        # id, the database will store it as a new document, and generate
        # a valid id.
        return self.db.create_doc(content)

    def get_all(self):
        """Get all messages"""
        return self.db.get_from_index(SEEN_INDEX, "*")

    def get_unseen(self):
        """Get only unseen messages"""
        return self.db.get_from_index(SEEN_INDEX, "0")

    def count(self):
        return len(self.get_all())


class SoledadMailbox:
    """
    A Soledad-backed IMAP mailbox
    """

    implements(imap4.IMailboxInfo, imap4.IMailbox, imap4.ICloseableMailbox)

    flags = ('\\Seen', '\\Answered', '\\Flagged',
             '\\Deleted', '\\Draft', '\\Recent', 'List')

    #messages = []
    messages = None
    mUID = 0
    rw = 1
    closed = False

    def __init__(self, mbox, soledad=None):
        # XXX sanity check:
        #soledad is not None and isinstance(SQLCipherDatabase, soldad._db)
        self.listeners = []
        self.addListener = self.listeners.append
        self.removeListener = self.listeners.remove
        self._soledad = soledad
        if soledad:
            self.messages = MessageCollection(
                mbox=mbox, db=soledad._db)

    def getFlags(self):
        return self.messages.db.get_index_keys(FLAGS_INDEX)

    def getUIDValidity(self):
        return 42

    def getUIDNext(self):
        return self.messages.count() + 1

    def getMessageCount(self):
        return self.messages.count()

    def getUnseenCount(self):
        return len(self.messages.get_unseen())

    def getRecentCount(self):
        # XXX
        return 3

    def isWriteable(self):
        return self.rw

    def destroy(self):
        pass

    def getHierarchicalDelimiter(self):
        return '/'

    def requestStatus(self, names):
        r = {}
        if 'MESSAGES' in names:
            r['MESSAGES'] = self.getMessageCount()
        if 'RECENT' in names:
            r['RECENT'] = self.getRecentCount()
        if 'UIDNEXT' in names:
            r['UIDNEXT'] = self.getMessageCount() + 1
        if 'UIDVALIDITY' in names:
            r['UIDVALIDITY'] = self.getUID()
        if 'UNSEEN' in names:
            r['UNSEEN'] = self.getUnseenCount()
        return defer.succeed(r)

    def addMessage(self, message, flags, date=None):
        # self.messages.add_msg((msg, flags, date, self.mUID))
        #self.messages.append((message, flags, date, self.mUID))
        # XXX CHANGE-ME
        self.messages.add_msg(subject=message, flags=flags, date=date)
        self.mUID += 1
        return defer.succeed(None)

    def deleteAllDocs(self):
        """deletes all docs"""
        docs = self.messages.db.get_all_docs()[1]
        for doc in docs:
            self.messages.db.delete_doc(doc)

    def expunge(self):
        """deletes all messages flagged \\Deleted"""
        # XXX FIXME!
        delete = []
        for i in self.messages:
            if '\\Deleted' in i[1]:
                delete.append(i)
        for i in delete:
            self.messages.remove(i)
        return [i[3] for i in delete]

    def close(self):
        self.closed = True
