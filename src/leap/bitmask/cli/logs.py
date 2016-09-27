# -*- coding: utf-8 -*-
# keys
# Copyright (C) 2016 LEAP
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
Bitmask Command Line interface: logs
"""
import argparse
import commands
import os.path
import sys

from colorama import Fore

from twisted.internet import defer
from twisted.python.procutils import which

from leap.bitmask.cli import command
from leap.common.config import get_path_prefix


class Logs(command.Command):
    usage = '''{name} logs <subcommand>

Bitmask Log Handling

SUBCOMMANDS:

   send       Send last bitmaskd log
'''.format(name=command.appname)

    def send(self, raw_args):
        _bin = which('pastebinit')
        if not _bin:
            error('pastebinit not found. install it to upload logs.')
            return defer.succeed(None)
        log_path = os.path.abspath(
            os.path.join(get_path_prefix(), 'leap', 'bitmaskd.log'))
        output = commands.getoutput('{0} -b {1} {2}'.format(
            _bin[0], 'paste.debian.net', log_path))
        uri = output.replace('debian.net/', 'debian.net/plain/')
        success(uri)
        return defer.succeed(None)


def error(msg):
    print Fore.RED + msg + Fore.RESET


def success(msg):
    print Fore.GREEN + '[+] Bitmaskd logs pasted to ' + msg + Fore.RESET
