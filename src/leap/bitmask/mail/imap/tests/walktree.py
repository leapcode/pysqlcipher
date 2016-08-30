# -*- coding: utf-8 -*-
# walktree.py
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
Tests for the walktree module.
"""
import os
import sys
import pprint
from email import parser

from leap.mail import walk as W

DEBUG = os.environ.get("BITMASK_MAIL_DEBUG")


p = parser.Parser()

# TODO pass an argument of the type of message

##################################################
# Input from hell

if len(sys.argv) > 1:
    FILENAME = sys.argv[1]
else:
    FILENAME = "rfc822.multi-signed.message"

"""
FILENAME = "rfc822.plain.message"
FILENAME = "rfc822.multi-minimal.message"
"""

msg = p.parse(open(FILENAME))
DO_CHECK = False
#################################################

parts = W.get_parts(msg)

if DEBUG:
    def trim(item):
        item = item[:10]
    [trim(part["phash"]) for part in parts if part.get('phash', None)]

raw_docs = list(W.get_raw_docs(msg, parts))

body_phash_fun = [W.get_body_phash_simple,
                  W.get_body_phash_multi][int(msg.is_multipart())]
body_phash = body_phash_fun(W.get_payloads(msg))
parts_map = W.walk_msg_tree(parts, body_phash=body_phash)


# TODO add missing headers!
expected = {
    'body': '1ddfa80485',
    'multi': True,
    'part_map': {
        1: {
            'headers': {'Content-Disposition': 'inline',
                        'Content-Type': 'multipart/mixed; '
                        'boundary="z0eOaCaDLjvTGF2l"'},
            'multi': True,
            'part_map': {1: {'ctype': 'text/plain',
                             'headers': [
                                 ('Content-Type',
                                  'text/plain; charset=utf-8'),
                                 ('Content-Disposition',
                                  'inline'),
                                 ('Content-Transfer-Encoding',
                                  'quoted-printable')],
                             'multi': False,
                             'parts': 1,
                             'phash': '1ddfa80485',
                             'size': 206},
                         2: {'ctype': 'text/plain',
                             'headers': [('Content-Type',
                                          'text/plain; charset=us-ascii'),
                                         ('Content-Disposition',
                                          'attachment; '
                                          'filename="attach.txt"')],
                             'multi': False,
                             'parts': 1,
                             'phash': '7a94e4d769',
                             'size': 133},
                         3: {'ctype': 'application/octet-stream',
                             'headers': [('Content-Type',
                                          'application/octet-stream'),
                                         ('Content-Disposition',
                                          'attachment; filename="hack.ico"'),
                                         ('Content-Transfer-Encoding',
                                          'base64')],
                             'multi': False,
                             'parts': 1,
                             'phash': 'c42cccebbd',
                             'size': 12736}}},
        2: {'ctype': 'application/pgp-signature',
            'headers': [('Content-Type', 'application/pgp-signature')],
            'multi': False,
            'parts': 1,
            'phash': '8f49fbf749',
            'size': 877}}}

if DEBUG and DO_CHECK:
    # TODO turn this into a proper unittest
    assert(parts_map == expected)
    print "Structure: OK"


print
print "RAW DOCS"
pprint.pprint(raw_docs)
print
print "PARTS MAP"
pprint.pprint(parts_map)
