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
Mail parser mixin.
"""
import re


class MBoxParser(object):
    """
    Utility function to parse mailbox names.
    """
    INBOX_NAME = "INBOX"
    INBOX_RE = re.compile(INBOX_NAME, re.IGNORECASE)

    def _parse_mailbox_name(self, name):
        """
        Return a normalized representation of the mailbox C{name}.

        This method ensures that an eventual initial 'inbox' part of a
        mailbox name is made uppercase.

        :param name: the name of the mailbox
        :type name: unicode

        :rtype: unicode
        """
        if self.INBOX_RE.match(name):
            # ensure inital INBOX is uppercase
            return self.INBOX_NAME + name[len(self.INBOX_NAME):]
        return name
