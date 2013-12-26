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
from leap.mail.imap.parser import MBoxParser


class WithMsgFields(object):
    """
    Container class for class-attributes to be shared by
    several message-related classes.
    """
    # Internal representation of Message
    DATE_KEY = "date"
    HEADERS_KEY = "headers"
    FLAGS_KEY = "flags"
    MBOX_KEY = "mbox"
    CONTENT_HASH_KEY = "chash"
    RAW_KEY = "raw"
    SUBJECT_KEY = "subject"
    UID_KEY = "uid"
    MULTIPART_KEY = "multi"
    SIZE_KEY = "size"

    # Mailbox specific keys
    CLOSED_KEY = "closed"
    CREATED_KEY = "created"
    SUBSCRIBED_KEY = "subscribed"
    RW_KEY = "rw"
    LAST_UID_KEY = "lastuid"

    # Document Type, for indexing
    TYPE_KEY = "type"
    TYPE_MBOX_VAL = "mbox"
    TYPE_MESSAGE_VAL = "msg"
    TYPE_FLAGS_VAL = "flags"
    TYPE_HEADERS_VAL = "head"
    TYPE_ATTACHMENT_VAL = "attach"
    # should add also a headers val

    INBOX_VAL = "inbox"

    # Flags for SoledadDocument for indexing.
    SEEN_KEY = "seen"
    RECENT_KEY = "recent"

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

    # Index  types
    # --------------

    TYPE_IDX = 'by-type'
    TYPE_MBOX_IDX = 'by-type-and-mbox'
    TYPE_MBOX_UID_IDX = 'by-type-and-mbox-and-uid'
    TYPE_SUBS_IDX = 'by-type-and-subscribed'
    TYPE_MBOX_SEEN_IDX = 'by-type-and-mbox-and-seen'
    TYPE_MBOX_RECT_IDX = 'by-type-and-mbox-and-recent'
    TYPE_HASH_IDX = 'by-type-and-hash'

    # Tomas created the `recent and seen index`, but the semantic is not too
    # correct since the recent flag is volatile.
    TYPE_MBOX_RECT_SEEN_IDX = 'by-type-and-mbox-and-recent-and-seen'

    KTYPE = TYPE_KEY
    MBOX_VAL = TYPE_MBOX_VAL
    HASH_VAL = CONTENT_HASH_KEY

    INDEXES = {
        # generic
        TYPE_IDX: [KTYPE],
        TYPE_MBOX_IDX: [KTYPE, MBOX_VAL],
        TYPE_MBOX_UID_IDX: [KTYPE, MBOX_VAL, UID_KEY],

        # mailboxes
        TYPE_SUBS_IDX: [KTYPE, 'bool(subscribed)'],

        # content, headers doc
        TYPE_HASH_IDX: [KTYPE, HASH_VAL],

        # messages
        TYPE_MBOX_SEEN_IDX: [KTYPE, MBOX_VAL, 'bool(seen)'],
        TYPE_MBOX_RECT_IDX: [KTYPE, MBOX_VAL, 'bool(recent)'],
        TYPE_MBOX_RECT_SEEN_IDX: [KTYPE, MBOX_VAL,
                                  'bool(recent)', 'bool(seen)'],
    }

    MBOX_KEY = MBOX_VAL

    EMPTY_MBOX = {
        TYPE_KEY: MBOX_KEY,
        TYPE_MBOX_VAL: MBoxParser.INBOX_NAME,
        SUBJECT_KEY: "",
        FLAGS_KEY: [],
        CLOSED_KEY: False,
        SUBSCRIBED_KEY: False,
        RW_KEY: 1,
        LAST_UID_KEY: 0
    }

fields = WithMsgFields  # alias for convenience
