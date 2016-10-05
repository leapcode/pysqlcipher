# -*- coding: utf-8 -*-
# _srp.py
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
SRP Authentication.
"""

from twisted.logger import Logger

import binascii
import json

import srp


log = Logger()


class SRPAuthMechanism(object):

    """
    Implement a protocol-agnostic SRP Authentication mechanism.
    """

    def __init__(self, username, password):
        self.username = username
        self.srp_user = srp.User(username, password,
                                 srp.SHA256, srp.NG_1024)
        _, A = self.srp_user.start_authentication()
        self.A = A
        self.M = None
        self.M2 = None

    def get_handshake_params(self):
        return {'login': bytes(self.username),
                'A': binascii.hexlify(self.A)}

    def process_handshake(self, handshake_response):
        challenge = json.loads(handshake_response)
        self._check_for_errors(challenge)
        salt = challenge.get('salt', None)
        B = challenge.get('B', None)
        unhex_salt, unhex_B = self._unhex_salt_B(salt, B)
        self.M = self.srp_user.process_challenge(unhex_salt, unhex_B)

    def get_authentication_params(self):
        # It looks A is not used server side
        return {'client_auth': binascii.hexlify(self.M),
                'A': binascii.hexlify(self.A)}

    def process_authentication(self, authentication_response):
        auth = json.loads(authentication_response)
        self._check_for_errors(auth)
        uuid = auth.get('id', None)
        token = auth.get('token', None)
        self.M2 = auth.get('M2', None)
        self._check_auth_params(uuid, token, self.M2)
        return uuid, token

    def verify_authentication(self):
        unhex_M2 = _safe_unhexlify(self.M2)
        self.srp_user.verify_session(unhex_M2)
        assert self.srp_user.authenticated()

    def _check_for_errors(self, response):
        if 'errors' in response:
            msg = response['errors']['base']
            raise SRPAuthError(unicode(msg).encode('utf-8'))

    def _unhex_salt_B(self, salt, B):
        if salt is None:
            raise SRPAuthNoSalt()
        if B is None:
            raise SRPAuthNoB()
        try:
            unhex_salt = _safe_unhexlify(salt)
            unhex_B = _safe_unhexlify(B)
        except (TypeError, ValueError) as e:
            raise SRPAuthBadDataFromServer(str(e))
        return unhex_salt, unhex_B

    def _check_auth_params(self, uuid, token, M2):
        if not all((uuid, token, M2)):
            msg = '%s' % str((M2, uuid, token))
            raise SRPAuthBadDataFromServer(msg)


class SRPSignupMechanism(object):

    """
    Implement a protocol-agnostic SRP Registration mechanism.
    """

    def get_signup_params(self, username, password, invite=None):
        salt, verifier = _get_salt_verifier(username, password)
        user_data = {
            'user[login]': username,
            'user[password_salt]': binascii.hexlify(salt),
            'user[password_verifier]': binascii.hexlify(verifier)}
        if invite is not None:
            user_data.update({'user[invite_code]': invite})
        return user_data

    def process_signup(self, signup_response):
        signup = json.loads(signup_response)
        errors = signup.get('errors')
        if errors:
            errmsg = json.dumps(errors)
            log.error('Oops! Errors during signup: {data!r}', data=errmsg)
            msg = errors.get('invite_code')
            if msg:
                msg = msg[0]
            else:
                msg = errors.get('login')
                if msg:
                    # there is a bug  https://leap.se/code/issues/8504
                    # the server tells us 'has already been taken' several
                    # times
                    msg = 'username ' + msg[0]
                else:
                    msg = 'unknown signup error'
            error = SRPRegistrationError(msg)
            error.expected = True
            raise error
        else:
            username = signup.get('login')
            return username


class SRPPasswordChangeMechanism(object):

    """
    Implement a protocol-agnostic SRP passord change mechanism.
    """

    def get_password_params(self, username, password):
        salt, verifier = _get_salt_verifier(username, password)
        user_data = {
            'user[password_salt]': binascii.hexlify(salt),
            'user[password_verifier]': binascii.hexlify(verifier)}
        return user_data


def _get_salt_verifier(username, password):
    return srp.create_salted_verification_key(bytes(username), bytes(password),
                                              srp.SHA256, srp.NG_1024)


def _safe_unhexlify(val):
    return binascii.unhexlify(val) \
        if (len(val) % 2 == 0) else binascii.unhexlify('0' + val)


class SRPAuthError(Exception):
    """
    Base exception for srp authentication errors
    """


class SRPAuthNoSalt(SRPAuthError):
    message = 'The server didn\'t send the salt parameter'


class SRPAuthNoB(SRPAuthError):
    message = 'The server didn\'t send the B parameter'


class SRPAuthBadDataFromServer(SRPAuthError):
    pass


class SRPRegistrationError(Exception):
    pass
