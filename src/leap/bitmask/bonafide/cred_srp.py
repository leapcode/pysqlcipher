# -*- coding: utf-8 -*-
# srp_cred.py
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
Credential module for authenticating SRP requests against the LEAP platform.
"""

# ----------------- DOC ------------------------------------------------------
# See examples of cred modules:
# https://github.com/oubiwann-unsupported/txBrowserID/blob/master/browserid/checker.py
# http://stackoverflow.com/questions/19171686/book-twisted-network-programming-essentials-example-9-1-does-not-work
# ----------------- DOC ------------------------------------------------------

from zope.interface import implements, implementer, Interface, Attribute

from twisted.cred import portal, credentials, error as credError
from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer, reactor

from leap.bitmask.bonafide.session import Session


@implementer(ICredentialsChecker)
class SRPCredentialsChecker(object):

    # TODO need to decide if the credentials that we pass here are per provider
    # or not.
    # I think it's better to have the credentials passed with the full user_id,
    # and here split user/provider.
    # XXX then we need to check if the provider is properly configured, to get
    # the right api info AND the needed certificates.
    # XXX might need to initialize credential checker with a ProviderAPI

    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, credentials):
        # TODO If we are already authenticated, we should just
        # return the session object, somehow.
        # XXX If not authenticated (ie, no cached credentials?)
        # we pass credentials to srpauth.authenticate method
        # another srpauth class should interface with the blocking srpauth
        # library, and chain all the calls needed to do the handshake.
        # Therefore:
        # should keep reference to the srpauth instances somewhere
        # TODO If we want to return an anonymous user (useful for getting the
        # anon-vpn cert), we should return an empty tuple from here.

        return defer.maybeDeferred(_get_leap_session(credentials)).addCallback(
            self._check_srp_auth)

    def _check_srp_auth(session, username):
        if session.is_authenticated:
            # is ok! --- should add it to some global cache?
            return defer.succeed(username)
        else:
            return defer.fail(credError.UnauthorizedLogin(
                "Bad username/password combination"))


def _get_leap_session(credentials):
    session = Session(credentials)
    d = session.authenticate()
    d.addCallback(lambda _: session)
    return d


class ILeapUserAvatar(Interface):

    # TODO add attributes for username, uuid, token, session_id

    def logout():
        """
        Clean up per-login resource allocated to this avatar.
        """


@implementer(ILeapUserAvatar)
class LeapUserAvatar(object):

    # TODO initialize with: username, uuid, token, session_id
    # TODO initialize provider data (for api)
    # TODO how does this relate to LeapSession? maybe we should get one passed?

    def logout(self):

        # TODO reset the (global?) srpauth object.
        # https://leap.se/en/docs/design/bonafide#logout
        # DELETE API_BASE/logout(.json)
        pass


class LeapAuthRealm(object):
    """
    The realm corresponds to an application domain and is in charge of avatars,
    which are network-accessible business logic objects.
    """

    # TODO should be initialized with provider API objects.

    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):

        if ILeapUserAvatar in interfaces:
            # XXX how should we get the details for the requested avatar?
            avatar = LeapUserAvatar()
            return ILeapUserAvatar, avatar, avatar.logout

        raise NotImplementedError(
            "This realm only supports the ILeapUserAvatar interface.")


if __name__ == '__main__':

    # XXX move boilerplate to some bitmask-core template.
    leap_realm = LeapAuthRealm()
    # XXX should pass a provider mapping to realm too?
    leap_portal = portal.Portal(leap_realm)
    # XXX should we add an offline credentials checker, that's able
    # to unlock local soledad sqlcipher backend?
    # XXX should pass a provider mapping to credentials checker too?
    srp_checker = SRPCredentialsChecker()
    leap_portal.registerChecker(srp_checker)

    # XXX tie this to some sample server...
    reactor.listenTCP(8000, EchoFactory(leap_portal))
    reactor.run()
