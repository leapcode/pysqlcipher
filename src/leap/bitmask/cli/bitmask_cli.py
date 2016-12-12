#!/usr/bin/env python
# -*- coding: utf-8 -*-
# bitmask_cli
# Copyright (C) 2015, 2016 LEAP
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
Bitmask Command Line interface: zmq client.
"""
import json
import sys
import signal

from colorama import Fore
from twisted.internet import reactor, defer

from leap.bitmask.cli.eip import Eip
from leap.bitmask.cli.keys import Keys
from leap.bitmask.cli.mail import Mail
from leap.bitmask.cli.webui import WebUI
from leap.bitmask.cli import command
from leap.bitmask.cli.user import User
from leap.bitmask.cli.logs import Logs


class BitmaskCLI(command.Command):
    usage = '''bitmaskctl <command> [<args>]

Controls the Bitmask application.

SERVICE COMMANDS:

  user       Handles Bitmask accounts
  mail       Bitmask Encrypted Mail
  eip        Encrypted Internet Proxy
  keys       Bitmask Keymanager
  ui         Bitmask User Interface
  logs       Manages bitmask daemon logs

GENERAL COMMANDS:

  version    prints version number and exit
  start      starts the Bitmask backend daemon
  stop       stops the Bitmask backend daemon
  status     displays general status about the running Bitmask services
  stats      show some debug info about bitmask-core
  help       show this help message

'''
    epilog = ("Use 'bitmaskctl <command> help' to learn more "
              "about each command.")

    def user(self, raw_args):
        user = User()
        return user.execute(raw_args)

    def mail(self, raw_args):
        mail = Mail()
        return mail.execute(raw_args)

    def eip(self, raw_args):
        eip = Eip()
        return eip.execute(raw_args)

    def keys(self, raw_args):
        keys = Keys()
        return keys.execute(raw_args)

    def ui(self, raw_args):
        webui = WebUI()
        return webui.execute(raw_args)

    def logs(self, raw_args):
        logs = Logs()
        return logs.execute(raw_args)

    # Single commands

    def start(self, raw_args):
        # XXX careful! Should see if the process in PID is running,
        # avoid launching again.
        import commands
        cmd = 'bitmaskd'
        if raw_args and ('--verbose' in raw_args or '-v' in raw_args):
            cmd += ' --verbose'
        commands.getoutput(cmd)
        return defer.succeed(None)

    def version(self, raw_args):
        self.data = ['core', 'version']
        return self._send(printer=self._print_version)

    def _print_version(self, version):
        corever = version['version_core']
        print(Fore.GREEN + 'bitmask_core: ' + Fore.RESET + corever)

    def status(self, raw_args):
        self.data = ['core', 'status']
        return self._send(printer=self._print_status)

    def _print_status(self, status):
        statusdict = json.loads(status)
        for key, value in statusdict.items():
            color = Fore.GREEN
            if value == 'stopped':
                color = Fore.RED
            print(key.ljust(10) + ': ' + color +
                  value + Fore.RESET)

    def stop(self, raw_args):
        self.data = ['core', 'stop']
        return self._send(printer=command.default_dict_printer)

    def stats(self, raw_args):
        self.data = ['core', 'stats']
        return self._send(printer=command.default_dict_printer)


@defer.inlineCallbacks
def execute():
    cli = BitmaskCLI()
    cli.data = ['core', 'version']
    args = ['--verbose'] if '--verbose' in sys.argv else None
    yield cli._send(
        timeout=0.1, printer=_null_printer,
        errb=lambda: cli.start(args))
    if 'start' in sys.argv or 'restart' in sys.argv:
        command.default_dict_printer({'start': 'ok'})
    cli.data = []
    yield cli.execute(sys.argv[1:])
    try:
        yield reactor.stop()
    except:
        pass


def _null_printer(*args):
    pass


def main():
    def signal_handler(signal, frame):
        if reactor.running:
            reactor.stop()
        sys.exit(0)

    reactor.callWhenRunning(reactor.callLater, 0, execute)
    signal.signal(signal.SIGINT, signal_handler)
    reactor.run()


if __name__ == "__main__":
    main()
