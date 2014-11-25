# -*- coding: utf-8 -*-
# interfaces.py
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
Interfaces for the leap.mail module.
"""
from zope.interface import Interface, Attribute


class IMessageWrapper(Interface):
    """
    I know how to access the different parts into which a given message is
    splitted into.
    """

    fdoc = Attribute('A dictionaly-like containing the flags document '
                     '(mutable)')
    hdoc = Attribute('A dictionary-like containing the headers docuemnt '
                     '(immutable)')
    cdocs = Attribute('A dictionary with the content-docs, one-indexed')


class IMailAdaptor(Interface):
    """
    I know how to store the standard representation for messages and mailboxes,
    and how to update the relevant mutable parts when needed.
    """

    def initialize_store(self, store):
        """
        Performs whatever initialization is needed before the store can be
        used (creating indexes, sanity checks, etc).

        :param store: store
        :returns: a Deferred that will fire when the store is correctly
                  initialized.
        :rtype: deferred
        """

    # TODO is staticmethod valid with an interface?
    # @staticmethod
    def get_msg_from_string(self, MessageClass, raw_msg):
        """
        Return IMessageWrapper implementor from a raw mail string

        :param MessageClass: an implementor of IMessage
        :type raw_msg: str
        :rtype: implementor of leap.mail.IMessage
        """

    # TODO is staticmethod valid with an interface?
    # @staticmethod
    def get_msg_from_docs(self, MessageClass, msg_wrapper):
        """
        Return an IMessage implementor from its parts.

        :param MessageClass: an implementor of IMessage
        :param msg_wrapper: an implementor of IMessageWrapper
        :rtype: implementor of leap.mail.IMessage
        """

    # -------------------------------------------------------------------
    # XXX unsure about the following part yet ...........................

    # the idea behind these three methods is that the adaptor also offers a
    # fixed interface to create the documents the first time (using
    # soledad.create_docs or whatever method maps to it in a similar store, and
    # also allows to update flags and tags, hiding the actual implementation of
    # where the flags/tags live in behind the concrete MailWrapper in use
    # by this particular adaptor. In our impl it will be put_doc(fdoc) after
    # locking the getting + updating of that fdoc for atomicity.

    # 'store' must be an instance of something that offers a minimal subset of
    # the document API that Soledad currently implements (create_doc, put_doc)
    # I *think* store should belong to Account/Collection and be passed as
    # param here instead of relying on it being an attribute of the instance.

    def create_msg_docs(self, store, msg_wrapper):
        """
        :param store: The documents store
        :type store:
        :param msg_wrapper:
        :type msg_wrapper: IMessageWrapper implementor
        """

    def update_msg_flags(self, store, msg_wrapper):
        """
        :param store: The documents store
        :type store:
        :param msg_wrapper:
        :type msg_wrapper: IMessageWrapper implementor
        """

    def update_msg_tags(self, store, msg_wrapper):
        """
        :param store: The documents store
        :type store:
        :param msg_wrapper:
        :type msg_wrapper: IMessageWrapper implementor
        """
