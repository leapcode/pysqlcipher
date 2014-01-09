# -*- coding: utf-8 -*-
# parser.py
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
Mail parser mixins.
"""
import cStringIO
import StringIO
import hashlib
import re

from email.message import Message
from email.parser import Parser

from leap.common.check import leap_assert_type


class MailParser(object):
    """
    Mixin with utility methods to parse raw messages.
    """
    def __init__(self):
        """
        Initializes the mail parser.
        """
        self._parser = Parser()

    def _get_parsed_msg(self, raw, headersonly=False):
        """
        Return a parsed Message.

        :param raw: the raw string to parse
        :type raw: basestring, or StringIO object

        :param headersonly: True for parsing only the headers.
        :type headersonly: bool
        """
        msg = self._get_parser_fun(raw)(raw, headersonly=headersonly)
        return msg

    def _get_hash(self, msg):
        """
        Returns a hash of the string representation of the raw message,
        suitable for indexing the inmutable pieces.

        :param msg: a Message object
        :type msg: Message
        """
        leap_assert_type(msg, Message)
        return hashlib.sha256(msg.as_string()).hexdigest()

    def _get_parser_fun(self, o):
        """
        Retunn the proper parser function for an object.

        :param o: object
        :type o: object
        :param parser: an instance of email.parser.Parser
        :type parser: email.parser.Parser
        """
        if isinstance(o, (cStringIO.OutputType, StringIO.StringIO)):
            return self._parser.parse
        if isinstance(o, basestring):
            return self._parser.parsestr
        # fallback
        return self._parser.parsestr

    def _stringify(self, o):
        """
        Return a string object.

        :param o: object
        :type o: object
        """
        # XXX Maybe we don't need no more, we're using
        # msg.as_string()
        if isinstance(o, (cStringIO.OutputType, StringIO.StringIO)):
            return o.getvalue()
        else:
            return o


class MBoxParser(object):
    """
    Utility function to parse mailbox names.
    """
    INBOX_NAME = "INBOX"
    INBOX_RE = re.compile(INBOX_NAME, re.IGNORECASE)

    def _parse_mailbox_name(self, name):
        """
        :param name: the name of the mailbox
        :type name: unicode

        :rtype: unicode
        """
        if self.INBOX_RE.match(name):
            # ensure inital INBOX is uppercase
            return self.INBOX_NAME + name[len(self.INBOX_NAME):]
        return name
