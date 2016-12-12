# -*- coding: utf-8 -*-
# dummy.py
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
An authoritative dummy backend for tests.
"""
import json

from leap.bitmask.hooks import HookableService


class CannedData:

    class backend:
        status = {
            'soledad': 'running',
            'keymanager': 'running',
            'mail': 'running',
            'eip': 'stopped',
            'backend': 'dummy'}
        version = {'version_core': '0.0.1'}
        stop = {'stop': 'ok'}
        stats = {'mem_usage': '01 KB'}

    class bonafide:
        auth = {
            u'lcl_token': u'deadbeef',
            u'srp_token': u'deadbeef123456789012345678901234567890123',
            u'uuid': u'01234567890abcde01234567890abcde'}
        signup = {
            'signup': 'ok',
            'user': 'dummyuser@provider.example.org'}
        list_users = {
            'userid': 'testuser',
            'authenticated': False}
        logout = {
            'logout': 'ok'}
        get_active_user = 'dummyuser@provider.example.org'
        change_password = {
            'update': 'ok'}


class BackendCommands(object):

    """
    General commands for the BitmaskBackend Core Service.
    """

    def __init__(self, core):
        self.core = core
        self.canned = CannedData

    def do_status(self):
        return json.dumps(self.canned.backend.stats)

    def do_version(self):
        return self.canned.backend.version

    def do_stats(self):
        return self.canned.backend.stats

    def do_stop(self):
        return self.canned.backend.stop


class mail_services(object):

    class SoledadService(HookableService):
        pass

    class KeymanagerService(HookableService):
        pass

    class StandardMailService(HookableService):
        pass


class BonafideService(HookableService):

    def __init__(self, basedir):
        self.canned = CannedData

    def do_authenticate(self, user, password, autoconf):
        return self.canned.bonafide.auth

    def do_signup(self, user, password, invite, autoconf):
        return self.canned.bonafide.signup

    def do_list_users(self):
        return self.canned.bonafide.list_users

    def do_logout(self, user):
        return self.canned.bonafide.logout

    def do_get_active_user(self):
        return self.canned.bonafide.get_active_user

    def do_change_password(self, username, old, new):
        return self.canned.bonafide.change_password
