import base64

from twisted.cred import portal
from twisted.trial import unittest
from twisted.web.test.test_web import DummyRequest
from twisted.web import resource

from leap.bitmask.core import _web


def b64encode(s):
    return base64.b64encode(s).strip()


class APIMixin:
    """
    L{TestCase} mixin class which defines a number of tests for
    L{basic.BasicCredentialFactory}.  Because this mixin defines C{setUp}, it
    must be inherited before L{TestCase}.
    """
    def setUp(self):
        self.request = self.makeRequest()

        api = AuthTestResource()
        self.realm = _web.HttpPasswordRealm(api)
        tokens = {'testuser': 'token'}
        checker = _web.TokenDictChecker(tokens)
        self.portal = portal.Portal(self.realm, [checker])

    def makeRequest(self, method=b'GET', clientAddress=None):
        """
        Create a request object to be passed to
        TokenCredentialFactory.decode along with a response value.
        Override this in a subclass.
        """
        raise NotImplementedError("%r did not implement makeRequest" % (
                                  self.__class__,))


class WhitelistedResourceTests(APIMixin, unittest.TestCase):

    def makeRequest(self, method=b'GET', clientAddress=None, path='/'):
        """
        Create a L{DummyRequest} (change me to create a
        L{twisted.web.http.Request} instead).
        """
        request = DummyRequest(b'/')
        request.method = method
        request.client = clientAddress
        request.path = path
        return request

    def test_render_returns_unauthorized_by_default(self):
        """
        By default, a Whitelisted resource renders with a 401 response code and
        a I{WWW-Authenticate} header and puts a simple unauthorized message
        into the response body.
        """
        protected = _web.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [_web.TokenCredentialFactory('localhost')])
        request = self.makeRequest(method='POST', path='/')
        request.render(protected)
        assert request.responseCode == 401

        auth_header = request.responseHeaders.getRawHeaders(
            b'www-authenticate')
        assert auth_header == [b'token realm="localhost"']
        assert b'Unauthorized' == b''.join(request.written)

    def test_whitelisted_resource_does_render(self):
        protected = _web.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [_web.TokenCredentialFactory('localhost')],
            whitelist=['/whitelisted'])
        request = self.makeRequest(method='GET', path='/whitelisted')
        request.render(protected)
        assert b'dummyGET' == b''.join(request.written)

    def test_good_token_authenticates(self):
        protected = _web.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [_web.TokenCredentialFactory('localhost')],
            whitelist=[])
        request = self.makeRequest(method='GET', path='/')
        authorization = b64encode(b'testuser:token')
        request.requestHeaders.addRawHeader(b'authorization',
                                            b'Token ' + authorization)
        request.render(protected)
        assert b'dummyGET' == b''.join(request.written)

    def test_session_does_not_use_cookies(self):
        # TODO
        pass


class AuthTestResource(resource.Resource):

    isLeaf = True

    def render_GET(self, request):
        return "dummyGET"

    def render_POST(self, request):
        return "dummyPOST"
