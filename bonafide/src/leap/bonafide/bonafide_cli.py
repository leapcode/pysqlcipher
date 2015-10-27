#!/usr/bin/env python
# -*- coding: utf-8 -*-
# bonafide_cli.py
# Copyright (C) 2015 LEAP
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
Command Line interface for bonafide cli.
"""

# XXX Warning! Work in progress------------------------------------------------
# This is just a demo, real cli will work against a persistent bonafide daemon.
# XXX -------------------------------------------------------------------------

import argparse
import os
import sys
from getpass import getpass

from colorama import init as color_init
from colorama import Fore

from twisted.cred.credentials import UsernamePassword
from twisted.internet import reactor

from leap.bonafide import provider
from leap.bonafide import session

COMMANDS = ('signup', 'authenticate')


def _cbShutDown(ignored):
    reactor.stop()


def _authEb(failure):
    print(Fore.RED + "[error] " + Fore.YELLOW +
          failure.getErrorMessage() + Fore.RESET)


def _display_token(result, _session):
    if result == session.OK:
        print('[ok] token--> ' + Fore.GREEN +
              _session.token + Fore.RESET)
        print('[ok] uuid --> ' + Fore.GREEN +
              _session.uuid + Fore.RESET)

def _display_registered(result, _session, _provider):
    ok, user = result
    if ok == session.OK:
        print('[ok] registered username--> ' + Fore.GREEN +
              '%s@%s' % (user, _provider))


def run_command(command, _provider, username, password):
    api = provider.Api('https://api.%s:4430' % _provider)
    credentials = UsernamePassword(username, password)
    cdev_pem = os.path.expanduser(
        '~/.config/leap/providers/%s/keys/ca/cacert.pem' % _provider)
    _session = session.Session(credentials, api, cdev_pem)

    if command == 'authenticate':
        d = _session.authenticate()
        d.addCallback(_display_token, _session)
    elif command == 'signup':
        d = _session.signup(username, password)
        d.addCallback(_display_registered, _session, _provider)
    else:
        print(Fore.YELLOW + "Command not implemented" + Fore.RESET)
        sys.exit()

    d.addErrback(_authEb)
    d.addCallback(lambda _: _session.logout())
    d.addBoth(_cbShutDown)
    reactor.run()

def main():
    color_init()
    description = (Fore.YELLOW + 'Manage and configure a LEAP Account '
        'using the bonafide protocol.' + Fore.RESET)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('command', type=str, choices=COMMANDS)
    parser.add_argument('--provider', dest='provider', required=True)
    parser.add_argument('--username', dest='username', required=True)

    ns = parser.parse_args()
    password = getpass(
        Fore.BLUE + '%s@%s password:' % (ns.username, ns.provider) + Fore.RESET)
    run_command(ns.command, ns.provider, ns.username, password)


if __name__ == '__main__':
    main()
