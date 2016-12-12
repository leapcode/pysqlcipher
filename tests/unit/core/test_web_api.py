import json
import base64

from twisted.application import service
from twisted.cred import portal
from twisted.internet import defer, reactor
from twisted.python.compat import networkString
from twisted.trial import unittest
from twisted.web import client
from twisted.web import resource
from twisted.web.server import Site
from twisted.web.test.test_web import DummyRequest

from leap.bitmask.core import dispatcher
from leap.bitmask.core import web
from leap.bitmask.core.dummy import mail_services
from leap.bitmask.core.dummy import BonafideService
from leap.bitmask.core.dummy import BackendCommands
from leap.bitmask.core.dummy import CannedData


def b64encode(s):
    return base64.b64encode(s).strip()


class SimpleAPIMixin:
    """
    L{TestCase} mixin class which defines a number of tests for
    L{basic.BasicCredentialFactory}.  Because this mixin defines C{setUp}, it
    must be inherited before L{TestCase}.

    The API resource in this case is just a very simple dummy request, doesn't
    implement any command dispatch.
    """
    def setUp(self):
        self.request = self.makeRequest()

        api = AuthTestResource()
        self.realm = web._auth.HttpPasswordRealm(api)
        tokens = {'testuser': 'token'}
        checker = web._auth.TokenDictChecker(tokens)
        self.portal = portal.Portal(self.realm, [checker])

    def makeRequest(self, method=b'GET', clientAddress=None):
        """
        Create a request object to be passed to
        TokenCredentialFactory.decode along with a response value.
        Override this in a subclass.
        """
        raise NotImplementedError("%r did not implement makeRequest" % (
                                  self.__class__,))


class WhitelistedResourceTests(SimpleAPIMixin, unittest.TestCase):

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
        protected = web._auth.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [web._auth.TokenCredentialFactory('localhost')])
        request = self.makeRequest(method='POST', path='/')
        request.render(protected)
        assert request.responseCode == 401

        auth_header = request.responseHeaders.getRawHeaders(
            b'www-authenticate')
        assert auth_header == [b'token realm="localhost"']
        assert b'Unauthorized' == b''.join(request.written)

    def test_whitelisted_resource_does_render(self):
        protected = web._auth.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [web._auth.TokenCredentialFactory('localhost')],
            whitelist=['/whitelisted'])
        request = self.makeRequest(method='GET', path='/whitelisted')
        request.render(protected)
        assert b'dummyGET' == b''.join(request.written)

    def test_good_token_authenticates(self):
        protected = web._auth.WhitelistHTTPAuthSessionWrapper(
            self.portal,
            [web._auth.TokenCredentialFactory('localhost')],
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


class RESTApiTests(unittest.TestCase):
    """
    Tests that involve checking the routing between the REST api and the
    command dispatcher.

    This is just really testing the canned responses in the Dummy backend.
    To make sure that those responses match the live data, e2e tests should be
    run.
    """

    def setUp(self):
        dispatcher = dummyDispatcherFactory()
        api = web.api.Api(dispatcher)
        plainSite = Site(api)
        self.plainPort = reactor.listenTCP(0, plainSite, interface="127.0.0.1")
        self.plainPortno = self.plainPort.getHost().port
        self.canned = CannedData

    def tearDown(self):
        return self.plainPort.stopListening()

    # core commands

    @defer.inlineCallbacks
    def test_core_version(self):
        call = yield self.makeAPICall('core/version')
        self.assertCall(call, self.canned.backend.version)

    @defer.inlineCallbacks
    def test_core_stop(self):
        call = yield self.makeAPICall('core/stop')
        self.assertCall(call, self.canned.backend.stop)

    # bonafide commands

    @defer.inlineCallbacks
    def test_bonafide_user_list(self):
        call = yield self.makeAPICall('bonafide/user/list')
        self.assertCall(call, self.canned.bonafide.list_users)

    @defer.inlineCallbacks
    def test_bonafide_user_create(self):
        call = yield self.makeAPICall('bonafide/user/create')
        self.assertCall(call, self.canned.bonafide.auth)

    @defer.inlineCallbacks
    def test_bonafide_user_update(self):
        call = yield self.makeAPICall('bonafide/user/update')
        self.assertCall(call, self.canned.bonafide.update)

    @defer.inlineCallbacks
    def test_bonafide_user_authenticate(self):
        call = yield self.makeAPICall('bonafide/user/authenticate')
        self.assertCall(call, self.canned.bonafide.auth)

    @defer.inlineCallbacks
    def test_bonafide_user_active(self):
        call = yield self.makeAPICall('bonafide/user/active')
        self.assertCall(call, self.canned.bonafide.get_active_user)

    @defer.inlineCallbacks
    def test_bonafide_user_logout(self):
        call = yield self.makeAPICall('bonafide/user/logout')
        self.assertCall(call, self.canned.bonafide.logout)

    def makeAPICall(self, path, method="POST"):
        uri = networkString("http://127.0.0.1:%d/%s" % (
            self.plainPortno, path))
        return client.getPage(uri, method=method, timeout=1)

    def assertCall(self, returned, expected):
        data = json.loads(returned)
        error = data['error']
        assert error is None
        result = data['result']
        assert result == expected


class DummyCore(service.MultiService):

    """
    A minimal core that uses the dummy backend modules.
    """

    def __init__(self):
        service.MultiService.__init__(self)

        bf = BonafideService
        self.init('bonafide', bf, '/tmp/')

        km = mail_services.KeymanagerService
        self.init('keymanager', km)

        sol = mail_services.SoledadService
        self.init('soledad', sol)

        mail = mail_services.StandardMailService
        self.init('mail', mail)

        self.core_cmds = BackendCommands(self)

    def init(self, label, service, *args, **kw):
        s = service(*args, **kw)
        s.setName(label)
        s.setServiceParent(self)

    def do_stats(self):
        return self.core_cmds.do_stats()

    def do_version(self):
        return self.core_cmds.do_version()

    def do_status(self):
        return self.core_cmds.do_status()

    def do_stop(self):
        return self.core_cmds.do_stop()


def dummyDispatcherFactory():
    """
    Returns a CommandDispatcher that uses the dummy backend
    """
    dummy_core = DummyCore()
    return dispatcher.CommandDispatcher(dummy_core)
