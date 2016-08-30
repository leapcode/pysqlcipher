# *- coding: utf-8 -*-
# constants.py
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
Constants for leap.mail.
"""

INBOX_NAME = "INBOX"

# Regular expressions for the identifiers to be used in the Message Data Layer.

METAMSGID = "M-{mbox_uuid}-{chash}"
METAMSGID_RE = "M\-{mbox_uuid}\-[0-9a-fA-F]+"
METAMSGID_CHASH_RE = "M\-\w+\-([0-9a-fA-F]+)"
METAMSGID_MBOX_RE = "M\-(\w+)\-[0-9a-fA-F]+"

FDOCID = "F-{mbox_uuid}-{chash}"
FDOCID_RE = "F\-{mbox_uuid}\-[0-9a-fA-F]+"
FDOCID_CHASH_RE = "F\-\w+\-([0-9a-fA-F]+)"

HDOCID = "H-{chash}"
HDOCID_RE = "H\-[0-9a-fA-F]+"

CDOCID = "C-{phash}"
CDOCID_RE = "C\-[0-9a-fA-F]+"


class MessageFlags(object):
    """
    Flags used in Message and Mailbox.
    """
    SEEN_FLAG = "\\Seen"
    RECENT_FLAG = "\\Recent"
    ANSWERED_FLAG = "\\Answered"
    FLAGGED_FLAG = "\\Flagged"  # yo dawg
    DELETED_FLAG = "\\Deleted"
    DRAFT_FLAG = "\\Draft"
    NOSELECT_FLAG = "\\Noselect"
    LIST_FLAG = "List"  # is this OK? (no \. ie, no system flag)
