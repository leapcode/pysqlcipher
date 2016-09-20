# -*- coding: utf-8 -*-
# util.py
# Copyright (C) 2016 LEAP Encryption Acess Project
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
Handy common utils
"""
import os
import platform
import sys

from twisted.python import log
from twisted.python.procutils import which


STANDALONE = getattr(sys, 'frozen', False)


def here(module=None):
    if STANDALONE:
        # we are running in a |PyInstaller| bundle
        return sys._MEIPASS
    else:
        dirname = os.path.dirname
        if module:
            return dirname(module.__file__)
        else:
            return dirname(__file__)


def get_gpg_bin_path():
    """
    Return the path to gpg binary.

    :returns: the gpg binary path
    :rtype: str
    """
    gpgbin = None

    # During the transition towards gpg2, we can look for /usr/bin/gpg1
    # binary, in case it was renamed using dpkg-divert or manually.
    # We could just pick gpg2, but we need to solve #7564 first.
    try:
        gpgbin_options = which("gpg1")
        for opt in gpgbin_options:
            if not os.path.islink(opt):
                gpgbin = opt
                break
    except IndexError as e:
        log.msg("Couldn't find the gpg1 binary!: %s" % (e,))
    if gpgbin is not None:
        return gpgbin

    if STANDALONE:
        gpgbin = os.path.join(
            get_path_prefix(), "..", "apps", "mail", "gpg")
        if platform.system() == "Windows":
            gpgbin += ".exe"
    else:
        try:
            gpgbin_options = which("gpg")
            # gnupg checks that the path to the binary is not a
            # symlink, so we need to filter those and come up with
            # just one option.
            for opt in gpgbin_options:
                if not os.path.islink(opt):
                    gpgbin = opt
                    break
        except IndexError as e:
            log.msg("Couldn't find the gpg binary!: %s" % (e,))
            log.exception(e)
    if platform.system() == "Darwin":
        gpgbin = os.path.abspath(
            os.path.join(here(), "apps", "mail", "gpg"))

    if gpgbin is None:
        log.msg("Could not find gpg1 binary")
    return gpgbin
