# -*- coding: utf-8 -*-
# mail.py
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
Generic Access to Mail objects: Public LEAP Mail API.
"""
from twisted.internet import defer

from leap.mail.constants import INBOX_NAME
from leap.mail.adaptors.soledad import SoledadMailAdaptor


# TODO
# [ ] Probably change the name of this module to "api" or "account", mail is
#     too generic (there's also IncomingMail, and OutgoingMail


class Message(object):

    def __init__(self, wrapper):
        """
        :param wrapper: an instance of an implementor of IMessageWrapper
        """
        self._wrapper = wrapper

    def get_wrapper(self):
        return self._wrapper

    # imap.IMessage methods

    def get_flags():
        """
        """

    def get_internal_date():
        """
        """

    # imap.IMessageParts

    def get_headers():
        """
        """

    def get_body_file():
        """
        """

    def get_size():
        """
        """

    def is_multipart():
        """
        """

    def get_subpart(part):
        """
        """

    # Custom methods.

    def get_tags():
        """
        """


class MessageCollection(object):
    """
    A generic collection of messages. It can be messages sharing the same
    mailbox, tag, the result of a given query, or just a bunch of ids for
    master documents.

    Since LEAP Mail is primarily oriented to store mail in Soledad, the default
    (and, so far, only) implementation of the store is contained in this
    Soledad Mail Adaptor. If you need to use a different adaptor, change the
    adaptor class attribute in your Account object.

    Store is a reference to a particular instance of the message store (soledad
    instance or proxy, for instance).
    """

    # TODO look at IMessageSet methods

    # Account should provide an adaptor instance when creating this collection.
    adaptor = None
    store = None

    def get_message_by_doc_id(self, doc_id):
        # ... get from soledad etc
        # ... but that should be part of adaptor/store too... :/
        fdoc, hdoc = None
        return self.adaptor.from_docs(Message, fdoc=fdoc, hdoc=hdoc)

    # TODO review if this is the best place for:

    def create_docs():
        pass

    def udpate_flags():
        # 1. update the flags in the message wrapper --- stored where???
        # 2. call adaptor.update_msg(store)
        pass

    def update_tags():
        # 1. update the tags in the message wrapper --- stored where???
        # 2. call adaptor.update_msg(store)
        pass

    # TODO add delete methods here?


class Account(object):
    """
    Account is the top level abstraction to access collections of messages
    associated with a LEAP Mail Account.

    It primarily handles creation and access of Mailboxes, which will be the
    basic collection handled by traditional MUAs, but it can also handle other
    types of Collections (tag based, for instance).

    leap.mail.imap.SoledadBackedAccount partially proxies methods in this
    class.
    """

    # Adaptor is passed to the returned MessageCollections, so if you want to
    # use a different adaptor this is the place to change it, by subclassing
    # the Account class.

    adaptor_class = SoledadMailAdaptor
    store = None
    mailboxes = None

    def __init__(self, store):
        self.store = store
        self.adaptor = self.adaptor_class()

        self.__mailboxes = set([])
        self._initialized = False
        self._deferred_initialization = defer.Deferred()

        self._initialize_storage()

    def _initialize_storage(self):

        def add_mailbox_if_none(result):
            # every user should have the right to an inbox folder
            # at least, so let's make one!
            if not self.mailboxes:
                self.add_mailbox(INBOX_NAME)

        def finish_initialization(result):
            self._initialized = True
            self._deferred_initialization.callback(None)

        def load_mbox_cache(result):
            d = self._load_mailboxes()
            d.addCallback(lambda _: result)
            return d

        d = self.adaptor.initialize_store(self.store)
        d.addCallback(load_mbox_cache)
        d.addCallback(add_mailbox_if_none)
        d.addCallback(finish_initialization)

    def callWhenReady(self, cb):
        # XXX this could use adaptor.store_ready instead...??
        if self._initialized:
            cb(self)
            return defer.succeed(None)
        else:
            self._deferred_initialization.addCallback(cb)
            return self._deferred_initialization

    @property
    def mailboxes(self):
        """
        A list of the current mailboxes for this account.
        :rtype: set
        """
        return sorted(self.__mailboxes)

    def _load_mailboxes(self):

        def update_mailboxes(mbox_names):
            self.__mailboxes.update(mbox_names)

        d = self.adaptor.get_all_mboxes(self.store)
        d.addCallback(update_mailboxes)
        return d

    #
    # Public API Starts
    #

    # XXX params for IMAP only???
    def list_mailboxes(self, ref, wildcard):
        self.adaptor.get_all_mboxes(self.store)

    def add_mailbox(self, name, mbox=None):
        pass

    def create_mailbox(self, pathspec):
        pass

    def delete_mailbox(self, name):
        pass

    def rename_mailbox(self, oldname, newname):
        pass

    # FIXME yet to be decided if it belongs here...

    def get_collection_by_mailbox(self, name):
        """
        :rtype: MessageCollection
        """
        # imap select will use this, passing the collection to SoledadMailbox
        # XXX pass adaptor to MessageCollection
        pass

    def get_collection_by_docs(self, docs):
        """
        :rtype: MessageCollection
        """
        # get a collection of docs by a list of doc_id
        # XXX pass adaptor to MessageCollection
        pass

    def get_collection_by_tag(self, tag):
        """
        :rtype: MessageCollection
        """
        # is this a good idea?
        pass
