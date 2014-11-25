# -*- coding: utf-8 -*-
# fields.py
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
Fields for Mailbox and Message.
"""

# TODO deprecate !!! (move all to constants maybe?)
# Flags -> foo


class WithMsgFields(object):
    """
    Container class for class-attributes to be shared by
    several message-related classes.
    """
    # Mailbox specific keys
    CREATED_KEY = "created"  # used???

    RECENTFLAGS_KEY = "rct"
    HDOCS_SET_KEY = "hdocset"

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


fields = WithMsgFields  # alias for convenience
