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
import os
import time
from functools import partial

from twisted.internet import defer
from twisted.logger import Logger
from twisted.mail import imap4
from zope.interface import implements

from leap.common.check import leap_assert, leap_assert_type
from leap.bitmask.mail.constants import MessageFlags
from leap.bitmask.mail.mail import Account
from leap.bitmask.mail.imap.mailbox import IMAPMailbox, normalize_mailbox
from leap.soledad.client import Soledad

logger = Logger()

PROFILE_CMD = os.environ.get('LEAP_PROFILE_IMAPCMD', False)

if PROFILE_CMD:
    def _debugProfiling(result, cmdname, start):
        took = (time.time() - start) * 1000
        logger.debug("CMD " + cmdname + " TOOK: " + str(took) + " msec")
        return result


#######################################
# Soledad IMAP Account
#######################################


class IMAPAccount(object):
    """
    An implementation of an imap4 Account
    that is backed by Soledad Encrypted Documents.
    """

    implements(imap4.IAccount, imap4.INamespacePresenter)

    selected = None

    def __init__(self, store, user_id, d=defer.Deferred()):
        """
        Keeps track of the mailboxes and subscriptions handled by this account.

        The account is not ready to be used, since the store needs to be
        initialized and we also need to do some initialization routines.
        You can either pass a deferred to this constructor, or use
        `callWhenReady` method.

        :param store: a Soledad instance.
        :type store: Soledad

        :param user_id: The identifier of the user this account belongs to
                        (user id, in the form user@provider).
        :type user_id: str


        :param d: a deferred that will be fired with this IMAPAccount instance
                  when the account is ready to be used.
        :type d: defer.Deferred
        """
        leap_assert(store, "Need a store instance to initialize")
        leap_assert_type(store, Soledad)

        # TODO assert too that the name matches the user/uuid with which
        # soledad has been initialized. Although afaik soledad doesn't know
        # about user_id, only the client backend.

        self.user_id = user_id
        self.account = Account(
            store, user_id, ready_cb=lambda: d.callback(self))

    def end_session(self):
        """
        Used to mark when the session has closed, and we should not allow any
        more commands from the client.

        Right now it's called from the client backend.
        """
        # TODO move its use to the service shutdown in leap.mail
        self.account.end_session()

    @property
    def session_ended(self):
        return self.account.session_ended

    def callWhenReady(self, cb, *args, **kw):
        """
        Execute callback when the account is ready to be used.
        XXX note that this callback will be called with a first ignored
        parameter.
        """
        # TODO ignore the first parameter and change tests accordingly.
        d = self.account.callWhenReady(cb, *args, **kw)
        return d

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
            return True

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_exists)
        d.addCallback(lambda _: self.account.get_collection_by_mailbox(name))
        d.addCallback(self._return_mailbox_from_collection)
        return d

    def _return_mailbox_from_collection(self, collection, readwrite=1):
        if collection is None:
            return None
        mbox = IMAPMailbox(collection, rw=readwrite)
        return mbox

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
        :rtype: defer.Deferred
        """
        name = normalize_mailbox(name)

        # FIXME --- return failure instead of AssertionError
        # See AccountTestCase...
        leap_assert(name, "Need a mailbox name to create a mailbox")

        def check_it_does_not_exist(mailboxes):
            if name in mailboxes:
                raise imap4.MailboxCollision, repr(name)
            return mailboxes

        d = self.account.list_all_mailbox_names()
        d.addCallback(check_it_does_not_exist)
        d.addCallback(lambda _: self.account.add_mailbox(
            name, creation_ts=creation_ts))
        d.addCallback(lambda _: self.account.get_collection_by_mailbox(name))
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
            succeeds. The deferred might fail with a MailboxException
            if the mailbox cannot be added.
        :rtype: Deferred

        """
        def pass_on_collision(failure):
            failure.trap(imap4.MailboxCollision)
            return True

        def handle_collision(failure):
            failure.trap(imap4.MailboxCollision)
            if not pathspec.endswith('/'):
                return defer.succeed(False)
            else:
                return defer.succeed(True)

        def all_good(result):
            return all(result)

        paths = filter(None, normalize_mailbox(pathspec).split('/'))
        subs = []
        sep = '/'

        for accum in range(1, len(paths)):
            partial_path = sep.join(paths[:accum])
            d = self.addMailbox(partial_path)
            d.addErrback(pass_on_collision)
            subs.append(d)

        df = self.addMailbox(sep.join(paths))
        df.addErrback(handle_collision)
        subs.append(df)

        d1 = defer.gatherResults(subs)
        d1.addCallback(all_good)
        return d1

    def select(self, name, readwrite=1):
        """
        Selects a mailbox.

        :param name: the mailbox to select
        :type name: str

        :param readwrite: 1 for readwrite permissions.
        :type readwrite: int

        :rtype: IMAPMailbox
        """
        name = normalize_mailbox(name)

        def check_it_exists(mailboxes):
            if name not in mailboxes:
                logger.warn('SELECT: No such mailbox!')
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

        :param name: the mailbox to be deleted
        :type name: str

        :param force:
            if True, it will not check for noselect flag or inferior
            names. use with care.
        :type force: bool
        :rtype: Deferred
        """
        name = normalize_mailbox(name)
        _mboxes = None

        def check_it_exists(mailboxes):
            global _mboxes
            _mboxes = mailboxes
            if name not in mailboxes:
                raise imap4.MailboxException("No such mailbox: %r" % name)

        def get_mailbox(_):
            return self.getMailbox(name)

        def destroy_mailbox(mbox):
            return mbox.destroy()

        def check_can_be_deleted(mbox):
            global _mboxes
            # See if this box is flagged \Noselect
            mbox_flags = mbox.getFlags()
            if MessageFlags.NOSELECT_FLAG in mbox_flags:
                # Check for hierarchically inferior mailboxes with this one
                # as part of their root.
                for others in _mboxes:
                    if others != name and others.startswith(name):
                        raise imap4.MailboxException(
                            "Hierarchically inferior mailboxes "
                            "exist and \\Noselect is set")
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

        def rename_inferiors((inferiors, mailboxes)):
            rename_deferreds = []
            inferiors = [
                (o, o.replace(oldname, newname, 1)) for o in inferiors]

            for (old, new) in inferiors:
                if new in mailboxes:
                    raise imap4.MailboxCollision(repr(new))

            for (old, new) in inferiors:
                d = self.account.rename_mailbox(old, new)
                rename_deferreds.append(d)

            d1 = defer.gatherResults(rename_deferreds, consumeErrors=True)
            return d1

        d1 = self._inferiorNames(oldname)
        d2 = self.account.list_all_mailbox_names()

        d = defer.gatherResults([d1, d2])
        d.addCallback(rename_inferiors)
        return d

    def _inferiorNames(self, name):
        """
        Return hierarchically inferior mailboxes.

        :param name: name of the mailbox
        :rtype: list
        """
        # XXX use wildcard query instead
        def filter_inferiors(mailboxes):
            inferiors = []
            for infname in mailboxes:
                if infname.startswith(name):
                    inferiors.append(infname)
            return inferiors

        d = self.account.list_all_mailbox_names()
        d.addCallback(filter_inferiors)
        return d

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
        wildcard = imap4.wildcardToRegexp(wildcard, '/')

        def get_list(mboxes, mboxes_names):
            return zip(mboxes_names, mboxes)

        def filter_inferiors(ref):
            mboxes = [mbox for mbox in ref if wildcard.match(mbox)]
            mbox_d = defer.gatherResults([self.getMailbox(m) for m in mboxes])

            mbox_d.addCallback(get_list, mboxes)
            return mbox_d

        d = self._inferiorNames(normalize_mailbox(ref))
        d.addCallback(filter_inferiors)
        return d

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
            return mbox.collection.get_mbox_attr("subscribed")

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
            return mbox.collection.set_mbox_attr("subscribed", True)

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
        # TODO should raise MailboxException if attempted to unsubscribe
        # from a mailbox that is not currently subscribed.
        # TODO factor out with subscribe method.
        name = normalize_mailbox(name)

        def set_unsubscribed(mbox):
            return mbox.collection.set_mbox_attr("subscribed", False)

        d = self.getMailbox(name)
        d.addCallback(set_unsubscribed)
        return d

    def getSubscriptions(self):
        def get_subscribed(mailboxes):
            return [x.mbox for x in mailboxes if x.subscribed]

        d = self.account.get_all_mailboxes()
        d.addCallback(get_subscribed)
        return d

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
