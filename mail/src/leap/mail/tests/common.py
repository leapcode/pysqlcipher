# -*- coding: utf-8 -*-
# common.py
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
Common utilities for testing Soledad.
"""
import os
import shutil
import tempfile

from twisted.internet import defer
from twisted.trial import unittest

from leap.common.testing.basetest import BaseLeapTest
from leap.soledad.client import Soledad

# TODO move to common module, or Soledad itself
# XXX remove duplication

TEST_USER = "testuser@leap.se"
TEST_PASSWD = "1234"


def _initialize_soledad(email, gnupg_home, tempdir):
    """
    Initializes soledad by hand

    :param email: ID for the user
    :param gnupg_home: path to home used by gnupg
    :param tempdir: path to temporal dir
    :rtype: Soledad instance
    """

    uuid = "foobar-uuid"
    passphrase = u"verysecretpassphrase"
    secret_path = os.path.join(tempdir, "secret.gpg")
    local_db_path = os.path.join(tempdir, "soledad.u1db")
    server_url = "https://provider"
    cert_file = ""

    soledad = Soledad(
        uuid,
        passphrase,
        secret_path,
        local_db_path,
        server_url,
        cert_file,
        syncable=False)

    return soledad


class SoledadTestMixin(unittest.TestCase, BaseLeapTest):
    """
    It is **VERY** important that this base is added *AFTER* unittest.TestCase
    """

    def setUp(self):
        self.results = []

        self.setUpEnv()

        # Soledad: config info
        self.gnupg_home = "%s/gnupg" % self.tempdir
        self.email = 'leap@leap.se'

        # initialize soledad by hand so we can control keys
        self._soledad = _initialize_soledad(
            self.email,
            self.gnupg_home,
            self.tempdir)

        return defer.succeed(True)

    def tearDown(self):
        """
        tearDown method called after each test.
        """
        self.results = []
        try:
            self._soledad.close()
        except Exception as exc:
            print "ERROR WHILE CLOSING SOLEDAD"
            # logging.exception(exc)
        finally:
            os.environ["PATH"] = self.old_path
            os.environ["HOME"] = self.old_home
            # safety check
            assert 'leap_tests-' in self.tempdir
            shutil.rmtree(self.tempdir)
