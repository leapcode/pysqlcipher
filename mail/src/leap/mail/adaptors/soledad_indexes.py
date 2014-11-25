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
#TYPE_MBOX_UID_IDX = 'by-type-and-mbox-and-uid'
TYPE_SUBS_IDX = 'by-type-and-subscribed'
TYPE_MSGID_IDX = 'by-type-and-message-id'
TYPE_MBOX_SEEN_IDX = 'by-type-and-mbox-and-seen'
TYPE_MBOX_RECT_IDX = 'by-type-and-mbox-and-recent'
TYPE_MBOX_DEL_IDX = 'by-type-and-mbox-and-deleted'
TYPE_MBOX_C_HASH_IDX = 'by-type-and-mbox-and-contenthash'
TYPE_C_HASH_IDX = 'by-type-and-contenthash'
TYPE_C_HASH_PART_IDX = 'by-type-and-contenthash-and-partnumber'
TYPE_P_HASH_IDX = 'by-type-and-payloadhash'

# Soledad index for incoming mail, without decrypting errors.
# and the backward-compatible index, will be deprecated at 0.7
JUST_MAIL_IDX = "just-mail"
JUST_MAIL_COMPAT_IDX = "just-mail-compat"

# Tomas created the `recent and seen index`, but the semantic is not too
# correct since the recent flag is volatile --- XXX review and delete.
#TYPE_MBOX_RECT_SEEN_IDX = 'by-type-and-mbox-and-recent-and-seen'

# TODO
# it would be nice to measure the cost of indexing
# by many fields.

# TODO
# make the indexes dict more readable!

MAIL_INDEXES = {
    # generic
    TYPE_IDX: [TYPE],
    TYPE_MBOX_IDX: [TYPE, MBOX],

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
    TYPE_MBOX_SEEN_IDX: [TYPE, MBOX, 'bool(seen)'],
    TYPE_MBOX_RECT_IDX: [TYPE, MBOX, 'bool(recent)'],
    TYPE_MBOX_DEL_IDX: [TYPE, MBOX, 'bool(deleted)'],
    #TYPE_MBOX_RECT_SEEN_IDX: [TYPE, MBOX,
                              #'bool(recent)', 'bool(seen)'],

    # incoming queue
    JUST_MAIL_IDX: [INCOMING_KEY,
                    "bool(%s)" % (ERROR_DECRYPTING_KEY,)],

    # the backward-compatible index, will be deprecated at 0.7
    JUST_MAIL_COMPAT_IDX: [INCOMING_KEY],
}
