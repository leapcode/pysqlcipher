# -*- coding: utf-8 -*-
# account.py
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
Soledad Backed IMAP Account.
"""
import logging
import os
import time
from functools import partial

from twisted.internet import defer
from twisted.mail import imap4
from twisted.python import log
from zope.interface import implements

from leap.common.check import leap_assert, leap_assert_type

from leap.mail.constants import MessageFlags
from leap.mail.mail import Account
from leap.mail.imap.mailbox import IMAPMailbox, normalize_mailbox
from leap.soledad.client import Soledad

logger = logging.getLogger(__name__)

PROFILE_CMD = os.environ.get('LEAP_PROFILE_IMAPCMD', False)

if PROFILE_CMD:
    def _debugProfiling(result, cmdname, start):
        took = (time.time() - start) * 1000
        log.msg("CMD " + cmdname + " TOOK: " + str(took) + " msec")
        return result


#######################################
# Soledad IMAP Account
#######################################

# XXX watchout, account needs to be ready... so we should maybe return
# a deferred to the IMAP service when it's initialized

class IMAPAccount(object):
    """
    An implementation of an imap4 Account
    that is backed by Soledad Encrypted Documents.
    """

    implements(imap4.IAccount, imap4.INamespacePresenter)

    selected = None
    closed = False

    def __init__(self, user_id, store):
        """
        Keeps track of the mailboxes and subscriptions handled by this account.

        :param account: The name of the account (user id).
        :type account: str

        :param store: a Soledad instance.
        :type store: Soledad
        """
        leap_assert(store, "Need a store instance to initialize")
        leap_assert_type(store, Soledad)

        # TODO assert too that the name matches the user/uuid with which
        # soledad has been initialized.
        self.user_id = user_id
        self.account = Account(store)

    def _return_mailbox_from_collection(self, collection, readwrite=1):
        if collection is None:
            return None
        return IMAPMailbox(collection, rw=readwrite)

    # XXX Where's this used from? -- self.delete...
    def getMailbox(self, name):
        """
        Return a Mailbox with that name, without selecting it.

        :param name: name of the mailbox
        :type name: str

        :returns: an IMAPMailbox instance
        :rtype: IMAPMailbox
        """
        name = normalize_mailbox(name)

        def check_it_exists(mailboxes):
            if name not in mailboxes:
                raise imap4.MailboxException("No such mailbox: %r" % name)

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_exists)
        d.addCallback(lambda _: self.account.get_collection_by_mailbox, name)
        d.addCallbacK(self._return_mailbox_from_collection)
        return d

    #
    # IAccount
    #

    def addMailbox(self, name, creation_ts=None):
        """
        Add a mailbox to the account.

        :param name: the name of the mailbox
        :type name: str

        :param creation_ts: an optional creation timestamp to be used as
                            mailbox id. A timestamp will be used if no
                            one is provided.
        :type creation_ts: int

        :returns: a Deferred that will contain the document if successful.
        :rtype: bool
        """
        name = normalize_mailbox(name)

        leap_assert(name, "Need a mailbox name to create a mailbox")

        def check_it_does_not_exist(mailboxes):
            if name in mailboxes:
                raise imap4.MailboxCollision(repr(name))

        if creation_ts is None:
            # by default, we pass an int value
            # taken from the current time
            # we make sure to take enough decimals to get a unique
            # mailbox-uidvalidity.
            creation_ts = int(time.time() * 10E2)

        def set_mbox_creation_ts(collection):
            d = collection.set_mbox_attr("created")
            d.addCallback(lambda _: collection)
            return d

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_does_not_exist)
        d.addCallback(lambda _: self.account.get_collection_by_mailbox, name)
        d.addCallback(set_mbox_creation_ts)
        d.addCallback(self._return_mailbox_from_collection)
        return d

    def create(self, pathspec):
        """
        Create a new mailbox from the given hierarchical name.

        :param pathspec:
            The full hierarchical name of a new mailbox to create.
            If any of the inferior hierarchical names to this one
            do not exist, they are created as well.
        :type pathspec: str

        :return:
            A deferred that will fire with a true value if the creation
            succeeds.
        :rtype: Deferred

        :raise MailboxException: Raised if this mailbox cannot be added.
        """
        # TODO raise MailboxException
        paths = filter(None, normalize_mailbox(pathspec).split('/'))

        subs = []
        sep = '/'

        for accum in range(1, len(paths)):
            try:
                partial_path = sep.join(paths[:accum])
                d = self.addMailbox(partial_path)
                subs.append(d)
            # XXX should this be handled by the deferred?
            except imap4.MailboxCollision:
                pass
        try:
            df = self.addMailbox(sep.join(paths))
        except imap4.MailboxCollision:
            if not pathspec.endswith('/'):
                df = defer.succeed(False)
            else:
                df = defer.succeed(True)
        finally:
            subs.append(df)

        def all_good(result):
            return all(result)

        if subs:
            d1 = defer.gatherResults(subs, consumeErrors=True)
            d1.addCallback(all_good)
        else:
            d1 = defer.succeed(False)
        return d1

    def select(self, name, readwrite=1):
        """
        Selects a mailbox.

        :param name: the mailbox to select
        :type name: str

        :param readwrite: 1 for readwrite permissions.
        :type readwrite: int

        :rtype: SoledadMailbox
        """
        name = normalize_mailbox(name)

        def check_it_exists(mailboxes):
            if name not in mailboxes:
                logger.warning("SELECT: No such mailbox!")
                return None
            return name

        def set_selected(_):
            self.selected = name

        def get_collection(name):
            if name is None:
                return None
            return self.account.get_collection_by_mailbox(name)

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_exists)
        d.addCallback(get_collection)
        d.addCallback(partial(
            self._return_mailbox_from_collection, readwrite=readwrite))
        return d

    def delete(self, name, force=False):
        """
        Deletes a mailbox.

        Right now it does not purge the messages, but just removes the mailbox
        name from the mailboxes list!!!

        :param name: the mailbox to be deleted
        :type name: str

        :param force:
            if True, it will not check for noselect flag or inferior
            names. use with care.
        :type force: bool
        :rtype: Deferred
        """
        name = normalize_mailbox(name)
        _mboxes = []

        def check_it_exists(mailboxes):
            # FIXME works? -- pass variable ref to outer scope
            _mboxes = mailboxes
            if name not in mailboxes:
                err = imap4.MailboxException("No such mailbox: %r" % name)
                return defer.fail(err)

        def get_mailbox(_):
            return self.getMailbox(name)

        def destroy_mailbox(mbox):
            return mbox.destroy()

        def check_can_be_deleted(mbox):
            # See if this box is flagged \Noselect
            mbox_flags = mbox.getFlags()
            if MessageFlags.NOSELECT_FLAG in mbox_flags:
                # Check for hierarchically inferior mailboxes with this one
                # as part of their root.
                for others in _mboxes:
                    if others != name and others.startswith(name):
                        err = imap4.MailboxException(
                            "Hierarchically inferior mailboxes "
                            "exist and \\Noselect is set")
                        return defer.fail(err)
            return mbox

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_exists)
        d.addCallback(get_mailbox)
        if not force:
            d.addCallback(check_can_be_deleted)
        d.addCallback(destroy_mailbox)
        return d

        # FIXME --- not honoring the inferior names...
        # if there are no hierarchically inferior names, we will
        # delete it from our ken.
        # XXX is this right?
        # if self._inferiorNames(name) > 1:
        #   self._index.removeMailbox(name)

    # TODO use mail.Account.rename_mailbox
    # TODO finish conversion to deferreds
    def rename(self, oldname, newname):
        """
        Renames a mailbox.

        :param oldname: old name of the mailbox
        :type oldname: str

        :param newname: new name of the mailbox
        :type newname: str
        """
        oldname = normalize_mailbox(oldname)
        newname = normalize_mailbox(newname)

        # FIXME check that scope works (test)
        _mboxes = []

        if oldname not in self.mailboxes:
            raise imap4.NoSuchMailbox(repr(oldname))

        inferiors = self._inferiorNames(oldname)
        inferiors = [(o, o.replace(oldname, newname, 1)) for o in inferiors]

        for (old, new) in inferiors:
            if new in _mboxes:
                raise imap4.MailboxCollision(repr(new))

        rename_deferreds = []

        for (old, new) in inferiors:
            d = self.account.rename_mailbox(old, new)
            rename_deferreds.append(d)

        d1 = defer.gatherResults(rename_deferreds, consumeErrors=True)
        return d1

    # FIXME use deferreds (list_all_mailbox_names, etc)
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

    # TODO use mail.Account.list_mailboxes
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
        # TODO get deferreds
        wildcard = imap4.wildcardToRegexp(wildcard, '/')
        ref = self._inferiorNames(normalize_mailbox(ref))
        return [(i, self.getMailbox(i)) for i in ref if wildcard.match(i)]

    #
    # The rest of the methods are specific for leap.mail.imap.account.Account
    #

    def isSubscribed(self, name):
        """
        Returns True if user is subscribed to this mailbox.

        :param name: the mailbox to be checked.
        :type name: str

        :rtype: Deferred (will fire with bool)
        """
        name = normalize_mailbox(name)

        def get_subscribed(mbox):
            return mbox.get_mbox_attr("subscribed")

        d = self.getMailbox(name)
        d.addCallback(get_subscribed)
        return d

    def subscribe(self, name):
        """
        Subscribe to this mailbox if not already subscribed.

        :param name: name of the mailbox
        :type name: str
        :rtype: Deferred
        """
        name = normalize_mailbox(name)

        def set_subscribed(mbox):
            return mbox.set_mbox_attr("subscribed", True)

        d = self.getMailbox(name)
        d.addCallback(set_subscribed)
        return d

    def unsubscribe(self, name):
        """
        Unsubscribe from this mailbox

        :param name: name of the mailbox
        :type name: str
        :rtype: Deferred
        """
        name = normalize_mailbox(name)

        def set_unsubscribed(mbox):
            return mbox.set_mbox_attr("subscribed", False)

        d = self.getMailbox(name)
        d.addCallback(set_unsubscribed)
        return d

    # TODO -- get__all_mboxes, return tuple
    # with ... name? and subscribed bool...
    def getSubscriptions(self):
        raise NotImplementedError()

    #
    # INamespacePresenter
    #

    def getPersonalNamespaces(self):
        return [["", "/"]]

    def getSharedNamespaces(self):
        return None

    def getOtherNamespaces(self):
        return None

    def __repr__(self):
        """
        Representation string for this object.
        """
        return "<IMAPAccount (%s)>" % self.user_id
