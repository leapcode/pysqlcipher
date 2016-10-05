# -*- coding: utf-8 -*-
# imap/messages.py
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
IMAPMessage implementation.
"""
from twisted.mail import imap4
from twisted.internet import defer
from twisted.logger import Logger
from zope.interface import implements

from leap.bitmask.mail.utils import find_charset, CaseInsensitiveDict


logger = Logger()

# TODO
# [ ] Add ref to incoming message during add_msg.


class IMAPMessage(object):
    """
    The main representation of a message as seen by the IMAP Server.
    This class implements the semantics specific to IMAP specification.
    """
    implements(imap4.IMessage)

    def __init__(self, message, prefetch_body=True,
                 store=None, d=defer.Deferred()):
        """
        Get an IMAPMessage. A mail.Message is needed, since many of the methods
        are proxied to that object.


        If you do not need to prefetch the body of the message, you can set
        `prefetch_body` to False, but the current imap server implementation
        expect the getBodyFile method to return inmediately.

        When the prefetch_body option is used, a deferred is also expected as a
        parameter, and this will fire when the deferred initialization has
        taken place, with this instance of IMAPMessage as a parameter.

        :param message: the abstract message
        :type message: mail.Message
        :param prefetch_body: Whether to prefetch the content doc for the body.
        :type prefetch_body: bool
        :param store: an instance of soledad, or anything that behaves like it.
        :param d: an optional deferred, that will be fired with the instance of
                  the IMAPMessage being initialized
        :type d: defer.Deferred
        """
        # TODO substitute the use of the deferred initialization by a factory
        # function, maybe.

        self.message = message
        self.__body_fd = None
        self.store = store
        if prefetch_body:
            gotbody = self.__prefetch_body_file()
            gotbody.addCallback(lambda _: d.callback(self))

    # IMessage implementation

    def getUID(self):
        """
        Retrieve the unique identifier associated with this Message.

        :return: uid for this message
        :rtype: int
        """
        return self.message.get_uid()

    def getFlags(self):
        """
        Retrieve the flags associated with this Message.

        :return: The flags, represented as strings
        :rtype: tuple
        """
        return self.message.get_flags()

    def getInternalDate(self):
        """
        Retrieve the date internally associated with this message

        According to the spec, this is NOT the date and time in the
        RFC-822 header, but rather a date and time that reflects when the
        message was received.

        * In SMTP, date and time of final delivery.
        * In COPY, internal date/time of the source message.
        * In APPEND, date/time specified.

        :return: An RFC822-formatted date string.
        :rtype: str
        """
        return self.message.get_internal_date()

    #
    # IMessagePart
    #

    def getBodyFile(self, store=None):
        """
        Retrieve a file object containing only the body of this message.

        :return: file-like object opened for reading
        :rtype: a deferred that will fire with a StringIO object.
        """
        if self.__body_fd is not None:
            fd = self.__body_fd
            fd.seek(0)
            return fd

        if store is None:
            store = self.store
        return self.message.get_body_file(store)

    def getSize(self):
        """
        Return the total size, in octets, of this message.

        :return: size of the message, in octets
        :rtype: int
        """
        return self.message.get_size()

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
        headers = self.message.get_headers()
        return _format_headers(headers, negate, *names)

    def isMultipart(self):
        """
        Return True if this message is multipart.
        """
        return self.message.is_multipart()

    def getSubPart(self, part):
        """
        Retrieve a MIME submessage

        :type part: C{int}
        :param part: The number of the part to retrieve, indexed from 0.
        :raise IndexError: Raised if the specified part does not exist.
        :raise TypeError: Raised if this message is not multipart.
        :rtype: Any object implementing C{IMessagePart}.
        :return: The specified sub-part.
        """
        subpart = self.message.get_subpart(part + 1)
        return IMAPMessagePart(subpart)

    def __prefetch_body_file(self):
        def assign_body_fd(fd):
            self.__body_fd = fd
            return fd
        d = self.getBodyFile()
        d.addCallback(assign_body_fd)
        return d


class IMAPMessagePart(object):

    def __init__(self, message_part):
        self.message_part = message_part

    def getBodyFile(self, store=None):
        return self.message_part.get_body_file()

    def getSize(self):
        return self.message_part.get_size()

    def getHeaders(self, negate, *names):
        headers = self.message_part.get_headers()
        return _format_headers(headers, negate, *names)

    def isMultipart(self):
        return self.message_part.is_multipart()

    def getSubPart(self, part):
        subpart = self.message_part.get_subpart(part + 1)
        return IMAPMessagePart(subpart)


def _format_headers(headers, negate, *names):
    # current server impl. expects content-type to be present, so if for
    # some reason we do not have headers, we have to return at least that
    # one
    if not headers:
        logger.warn("No headers found")
        return {str('content-type'): str('')}

    names = map(lambda s: s.upper(), names)

    if negate:
        def cond(key):
            return key.upper() not in names
    else:
        def cond(key):
            return key.upper() in names

    if isinstance(headers, list):
        headers = dict(headers)

    # default to most likely standard
    charset = find_charset(headers, "utf-8")

    # We will return a copy of the headers dictionary that
    # will allow case-insensitive lookups. In some parts of the twisted imap
    # server code the keys are expected to be in lower case, and in this way
    # we avoid having to convert them.

    _headers = CaseInsensitiveDict()
    for key, value in headers.items():
        if not isinstance(key, str):
            key = key.encode(charset, 'replace')
        if not isinstance(value, str):
            value = value.encode(charset, 'replace')

        if value.endswith(";"):
            # bastards
            value = value[:-1]

        # filter original dict by negate-condition
        if cond(key):
            _headers[key] = value

    return _headers
