# -*- coding: utf-8 -*-
# walk.py
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
Walk a message tree and generate documents that can be inserted in the backend
store.
"""
from email.parser import Parser

from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.backends.openssl.backend import (
    Backend as OpenSSLBackend)
from cryptography.hazmat.primitives import hashes

from leap.bitmask.mail.utils import first

crypto_backend = MultiBackend([OpenSSLBackend()])

_parser = Parser()


def get_tree(msg):
    p = {}
    p['ctype'] = msg.get_content_type()
    p['headers'] = msg.items()

    payload = msg.get_payload()
    is_multi = msg.is_multipart()
    if is_multi:
        p['part_map'] = dict(
            [(idx, get_tree(part)) for idx, part in enumerate(payload, 1)])
        p['parts'] = len(payload)
        p['phash'] = None
    else:
        p['parts'] = 0
        p['size'] = len(payload)
        p['phash'] = get_hash(payload)
        p['part_map'] = {}
    p['multi'] = is_multi
    return p


def get_tree_from_string(messagestr):
    return get_tree(_parser.parsestr(messagestr))


def get_body_phash(msg):
    """
    Find the body payload-hash for this message.
    """
    for part in msg.walk():
        # XXX what other ctypes should be considered body?
        if part.get_content_type() in ("text/plain", "text/html"):
            # XXX avoid hashing again
            return get_hash(part.get_payload())


def get_raw_docs(msg):
    """
    We get also some of the headers to be able to
    index the content. Here we remove any mutable part, as the the filename
    in the content disposition.
    """
    return (
        {'type': 'cnt',
         'raw': part.get_payload(),
         'phash': get_hash(part.get_payload()),
         'content-type': part.get_content_type(),
         'charset': part.get_content_charset(),
         'content-disposition': first(part.get(
             'content-disposition', '').split(';')),
         'content-transfer-encoding': part.get(
             'content-transfer-encoding', '')
         } for part in msg.walk() if not isinstance(part.get_payload(), list))


def get_hash(s):
    digest = hashes.Hash(hashes.SHA256(), crypto_backend)
    digest.update(s)
    return digest.finalize().encode("hex").upper()


"""
Groucho Marx: Now pay particular attention to this first clause, because it's
              most important. There's the party of the first part shall be
              known in this contract as the party of the first part. How do you
              like that, that's pretty neat eh?

Chico Marx: No, that's no good.
Groucho Marx: What's the matter with it?

Chico Marx: I don't know, let's hear it again.
Groucho Marx: So the party of the first part shall be known in this contract as
              the party of the first part.
"""
