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
Interfaces for the IMAP module.
"""
from zope.interface import Interface, Attribute


# TODO remove  ----------------
class IMessageContainer(Interface):
    """
    I am a container around the different documents that a message
    is split into.
    """
    fdoc = Attribute('The flags document for this message, if any.')
    hdoc = Attribute('The headers document for this message, if any.')
    cdocs = Attribute('The dict of content documents for this message, '
                      'if any.')

    def walk(self):
        """
        Return an iterator to the docs for all the parts.

        :rtype: iterator
        """


# TODO remove --------------------
class IMessageStore(Interface):
    """
    I represent a generic storage for LEAP Messages.
    """

    def create_message(self, mbox, uid, message):
        """
        Put the passed message into this IMessageStore.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        :param message: a IMessageContainer implementor.
        """

    def put_message(self, mbox, uid, message):
        """
        Put the passed message into this IMessageStore.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        :param message: a IMessageContainer implementor.
        """

    def remove_message(self, mbox, uid):
        """
        Remove the given message from this IMessageStore.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        """

    def get_message(self, mbox, uid):
        """
        Get a IMessageContainer for the given mbox and uid combination.

        :param mbox: the mbox this message belongs.
        :param uid: the UID that identifies this message in this mailbox.
        :return: IMessageContainer
        """


class IMessageStoreWriter(Interface):
    """
    I represent a storage that is able to write its contents to another
    different IMessageStore.
    """

    def write_messages(self, store):
        """
        Write the documents in this IMessageStore to a different
        storage. Usually this will be done from a MemoryStorage to a DbStorage.

        :param store: another IMessageStore implementor.
        """
