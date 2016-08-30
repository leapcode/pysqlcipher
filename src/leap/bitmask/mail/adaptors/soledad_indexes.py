# -*- coding: utf-8 -*-
# soledad_indexes.py
# Copyright (C) 2013, 2014 LEAP
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
Soledad Indexes for Mail Documents.
"""

# TODO
# [ ] hide most of the constants here

# Document Type, for indexing

TYPE = "type"
MBOX = "mbox"
MBOX_UUID = "mbox_uuid"
FLAGS = "flags"
HEADERS = "head"
CONTENT = "cnt"
RECENT = "rct"
HDOCS_SET = "hdocset"

INCOMING_KEY = "incoming"
ERROR_DECRYPTING_KEY = "errdecr"

# indexing keys
CONTENT_HASH = "chash"
PAYLOAD_HASH = "phash"
MSGID = "msgid"
UID = "uid"


# Index  types
# --------------

TYPE_IDX = 'by-type'
TYPE_MBOX_IDX = 'by-type-and-mbox'
TYPE_MBOX_UUID_IDX = 'by-type-and-mbox-uuid'
TYPE_SUBS_IDX = 'by-type-and-subscribed'
TYPE_MSGID_IDX = 'by-type-and-message-id'
TYPE_MBOX_SEEN_IDX = 'by-type-and-mbox-and-seen'
TYPE_MBOX_RECENT_IDX = 'by-type-and-mbox-and-recent'
TYPE_MBOX_DEL_IDX = 'by-type-and-mbox-and-deleted'
TYPE_MBOX_C_HASH_IDX = 'by-type-and-mbox-and-contenthash'
TYPE_C_HASH_IDX = 'by-type-and-contenthash'
TYPE_C_HASH_PART_IDX = 'by-type-and-contenthash-and-partnumber'
TYPE_P_HASH_IDX = 'by-type-and-payloadhash'

# Soledad index for incoming mail, without decrypting errors.
# and the backward-compatible index, will be deprecated at 0.7
JUST_MAIL_IDX = "just-mail"
JUST_MAIL_COMPAT_IDX = "just-mail-compat"


# TODO
# it would be nice to measure the cost of indexing
# by many fields.

# TODO
# make the indexes dict more readable!

MAIL_INDEXES = {
    # generic
    TYPE_IDX: [TYPE],
    TYPE_MBOX_IDX: [TYPE, MBOX],
    TYPE_MBOX_UUID_IDX: [TYPE, MBOX_UUID],

    # XXX deprecate 0.4.0
    # TYPE_MBOX_UID_IDX: [TYPE, MBOX, UID],

    # mailboxes
    TYPE_SUBS_IDX: [TYPE, 'bool(subscribed)'],

    # fdocs uniqueness
    TYPE_MBOX_C_HASH_IDX: [TYPE, MBOX, CONTENT_HASH],

    # headers doc - search by msgid.
    TYPE_MSGID_IDX: [TYPE, MSGID],

    # content, headers doc
    TYPE_C_HASH_IDX: [TYPE, CONTENT_HASH],

    # attachment payload dedup
    TYPE_P_HASH_IDX: [TYPE, PAYLOAD_HASH],

    # messages
    TYPE_MBOX_SEEN_IDX: [TYPE, MBOX_UUID, 'bool(seen)'],
    TYPE_MBOX_RECENT_IDX: [TYPE, MBOX_UUID, 'bool(recent)'],
    TYPE_MBOX_DEL_IDX: [TYPE, MBOX_UUID, 'bool(deleted)'],

    # incoming queue
    JUST_MAIL_IDX: ["bool(%s)" % (INCOMING_KEY,),
                    "bool(%s)" % (ERROR_DECRYPTING_KEY,)],
}
