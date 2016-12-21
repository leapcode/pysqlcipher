from zope.interface import implementer

from twisted.cred import portal, checkers, credentials, error as credError
from twisted.internet import defer
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory
from twisted.web.resource import IResource


class TokenCredentialFactory(BasicCredentialFactory):
    scheme = 'token'


@implementer(IResource)
class WhitelistHTTPAuthSessionWrapper(HTTPAuthSessionWrapper):

    """
    Wrap a portal, enforcing supported header-based authentication schemes.
    It doesn't apply the enforcement to routes included in a whitelist.
    """

    whitelist = (None,)

    def __init__(self, *args, **kw):
        self.whitelist = kw.pop('whitelist', tuple())
        super(WhitelistHTTPAuthSessionWrapper, self).__init__(
            *args, **kw)

    def getChildWithDefault(self, path, request):
        if request.path in self.whitelist:
            return self
        return HTTPAuthSessionWrapper.getChildWithDefault(self, path, request)

    def render(self, request):
        if request.path in self.whitelist:
            _res = self._portal.realm.resource
            return _res.render(request)
        return HTTPAuthSessionWrapper.render(self, request)


def protectedResourceFactory(resource, session_tokens, whitelist):
    realm = HttpPasswordRealm(resource)
    checker = TokenDictChecker(session_tokens)
    resource_portal = portal.Portal(realm, [checker])
    credentialFactory = TokenCredentialFactory('localhost')
    protected_resource = WhitelistHTTPAuthSessionWrapper(
        resource_portal, [credentialFactory],
        whitelist=whitelist)
    return protected_resource


@implementer(checkers.ICredentialsChecker)
class TokenDictChecker:

    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, tokens):
        self.tokens = tokens

    def requestAvatarId(self, credentials):
        username = credentials.username
        if username in self.tokens:
            if credentials.checkPassword(self.tokens[username]):
                return defer.succeed(username)
            else:
                return defer.fail(
                    credError.UnauthorizedLogin("Bad session token"))
        else:
            return defer.fail(
                credError.UnauthorizedLogin("No such user"))


@implementer(portal.IRealm)
class HttpPasswordRealm(object):

    def __init__(self, resource):
        self.resource = resource

    def requestAvatar(self, user, mind, *interfaces):
        # the resource is passed on regardless of user
        if IResource in interfaces:
            return (IResource, self.resource, lambda: None)
        raise NotImplementedError()
