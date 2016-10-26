# -*- coding: utf-8 -*-
# uuid_map.py
# Copyright (C) 2015,2016 LEAP
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
UUID Map: a persistent mapping between user-ids and uuids.
"""

import base64
import os
import re
import platform

import scrypt

from leap.common.config import get_path_prefix

IS_WIN = platform.system() == "Windows"

if IS_WIN:
    import socket
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends.multibackend import MultiBackend
    from cryptography.hazmat.backends.openssl.backend \
        import Backend as OpenSSLBackend
    crypto_backend = MultiBackend([OpenSSLBackend()])


MAP_PATH = os.path.join(get_path_prefix(), 'leap', 'uuids')


class UserMap(object):

    """
    A persistent mapping between user-ids and uuids.
    """

    # TODO Add padding to the encrypted string

    def __init__(self):
        self._d = {}
        self._lines = set([])
        if os.path.isfile(MAP_PATH):
            self.load()

    def add(self, userid, uuid, passwd):
        """
        Add a new userid-uuid mapping, and encrypt the record with the user
        password.
        """
        self._add_to_cache(userid, uuid)
        self._lines.add(_encode_uuid_map(userid, uuid, passwd))
        self.dump()

    def _add_to_cache(self, userid, uuid):
        self._d[userid] = uuid

    def load(self):
        """
        Load a mapping from a default file.
        """
        with open(MAP_PATH, 'r') as infile:
            lines = infile.readlines()
            self._lines = set(lines)

    def dump(self):
        """
        Dump the mapping to a default file.
        """
        with open(MAP_PATH, 'w') as out:
            out.write('\n'.join(self._lines))

    def lookup_uuid(self, userid, passwd=None):
        """
        Lookup the uuid for a given userid.

        If no password is given, try to lookup on cache.
        Else, try to decrypt all the records that we know about with the
        passed password.
        """
        if not passwd:
            return self._d.get(userid)

        for line in self._lines:
            guess = _decode_uuid_line(line, passwd)
            if guess:
                record_userid, uuid = guess
                if record_userid == userid:
                    self._add_to_cache(userid, uuid)
                    return uuid

    def lookup_userid(self, uuid):
        """
        Get the userid for the given uuid from cache.
        """
        rev_d = {v: k for (k, v) in self._d.items()}
        return rev_d.get(uuid)


def _encode_uuid_map(userid, uuid, passwd):
    data = 'userid:%s:uuid:%s' % (userid, uuid)

    # FIXME scrypt.encrypt is broken in windows.
    # This is a quick hack. The hostname might not be unique enough though.
    # We could use a long random hash per entry and store it in the file.
    # Other option is to use a different KDF that is supported by cryptography
    # (ie, pbkdf)

    if IS_WIN:
        key = scrypt.hash(passwd, socket.gethostname())
        key = base64.urlsafe_b64encode(key[:32])
        f = Fernet(key, backend=crypto_backend)
        encrypted = f.encrypt(data)
    else:
        encrypted = scrypt.encrypt(data, passwd, maxtime=0.05)
    return base64.urlsafe_b64encode(encrypted)


def _decode_uuid_line(line, passwd):
    decoded = base64.urlsafe_b64decode(line)
    if IS_WIN:
        key = scrypt.hash(passwd, socket.gethostname())
        key = base64.urlsafe_b64encode(key[:32])
        try:
            f = Fernet(key, backend=crypto_backend)
            maybe_decrypted = f.decrypt(key)
        except Exception:
            return None
    else:
        try:
            maybe_decrypted = scrypt.decrypt(decoded, passwd, maxtime=0.1)
        except scrypt.error:
            return None
    match = re.findall("userid\:(.+)\:uuid\:(.+)", maybe_decrypted)
    if match:
        return match[0]
