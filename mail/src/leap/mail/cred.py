# -*- coding: utf-8 -*-
# cred.py
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
Credentials handling.
"""

from zope.interface import implementer
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import defer


@implementer(ICredentialsChecker)
class LocalSoledadTokenChecker(object):

    """
    A Credentials Checker for a LocalSoledad store.

    It checks that:

    1) The Local SoledadStorage has been correctly unlocked for the given
       user. This currently means that the right passphrase has been passed
       to the Local SoledadStorage.

    2) The password passed in the credentials matches whatever token has
       been stored in the local encrypted SoledadStorage, associated to the
       Protocol that is requesting the authentication.
    """

    credentialInterfaces = (IUsernamePassword,)
    service = None

    def __init__(self, soledad_sessions):
        """
        :param soledad_sessions: a dict-like object, containing instances
                                 of a Store (soledad instances), indexed by
                                 userid.
        """
        self._soledad_sessions = soledad_sessions

    def requestAvatarId(self, credentials):
        if self.service is None:
            raise NotImplementedError(
                "this checker has not defined its service name")
        username, password = credentials.username, credentials.password
        d = self.checkSoledadToken(username, password, self.service)
        d.addErrback(lambda f: defer.fail(UnauthorizedLogin()))
        return d

    def checkSoledadToken(self, username, password, service):
        soledad = self._soledad_sessions.get(username)
        if not soledad:
            return defer.fail(Exception("No soledad"))

        def match_token(token):
            if token is None:
                raise RuntimeError('no token')
            if token == password:
                return username
            else:
                raise RuntimeError('bad token')

        d = soledad.get_or_create_service_token(service)
        d.addCallback(match_token)
        return d
