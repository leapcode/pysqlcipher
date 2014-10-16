import os
import tempfile
import shutil

from email import parser

from mock import Mock
from twisted.mail import imap4
from twisted.internet import defer
from twisted.protocols import loopback

from leap.common.testing.basetest import BaseLeapTest
from leap.mail.imap.account import SoledadBackedAccount
from leap.mail.imap.memorystore import MemoryStore
from leap.mail.imap.server import LeapIMAPServer
from leap.soledad.client import Soledad

TEST_USER = "testuser@leap.se"
TEST_PASSWD = "1234"

#
# Simple IMAP4 Client for testing
#


class SimpleClient(imap4.IMAP4Client):

    """
    A Simple IMAP4 Client to test our
    Soledad-LEAPServer
    """

    def __init__(self, deferred, contextFactory=None):
        imap4.IMAP4Client.__init__(self, contextFactory)
        self.deferred = deferred
        self.events = []

    def serverGreeting(self, caps):
        self.deferred.callback(None)

    def modeChanged(self, writeable):
        self.events.append(['modeChanged', writeable])
        self.transport.loseConnection()

    def flagsChanged(self, newFlags):
        self.events.append(['flagsChanged', newFlags])
        self.transport.loseConnection()

    def newMessages(self, exists, recent):
        self.events.append(['newMessages', exists, recent])
        self.transport.loseConnection()


def initialize_soledad(email, gnupg_home, tempdir):
    """
    Initializes soledad by hand

    :param email: ID for the user
    :param gnupg_home: path to home used by gnupg
    :param tempdir: path to temporal dir
    :rtype: Soledad instance
    """

    uuid = "foobar-uuid"
    passphrase = u"verysecretpassphrase"
    secret_path = os.path.join(tempdir, "secret.gpg")
    local_db_path = os.path.join(tempdir, "soledad.u1db")
    server_url = "https://provider"
    cert_file = ""

    class MockSharedDB(object):

        get_doc = Mock(return_value=None)
        put_doc = Mock()
        lock = Mock(return_value=('atoken', 300))
        unlock = Mock(return_value=True)

        def __call__(self):
            return self

    Soledad._shared_db = MockSharedDB()

    _soledad = Soledad(
        uuid,
        passphrase,
        secret_path,
        local_db_path,
        server_url,
        cert_file,
        syncable=False)

    return _soledad


# XXX this is not properly a mixin, since helper already inherits from
# uniittest.Testcase
class IMAP4HelperMixin(BaseLeapTest):
    """
    MixIn containing several utilities to be shared across
    different TestCases
    """

    serverCTX = None
    clientCTX = None

    # setUpClass cannot be a classmethod in trial, see:
    # https://twistedmatrix.com/trac/ticket/1870

    def setUp(self):
        """
        Setup method for each test.

        Initializes and run a LEAP IMAP4 Server,
        but passing the same Soledad instance (it's costly to initialize),
        so we have to be sure to restore state across tests.
        """
        self.old_path = os.environ['PATH']
        self.old_home = os.environ['HOME']
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self.home = self.tempdir
        bin_tdir = os.path.join(
            self.tempdir,
            'bin')
        os.environ["PATH"] = bin_tdir
        os.environ["HOME"] = self.tempdir

        # Soledad: config info
        self.gnupg_home = "%s/gnupg" % self.tempdir
        self.email = 'leap@leap.se'

        # initialize soledad by hand so we can control keys
        self._soledad = initialize_soledad(
            self.email,
            self.gnupg_home,
            self.tempdir)
        UUID = 'deadbeef',
        USERID = TEST_USER
        memstore = MemoryStore()

        ###########

        d_server_ready = defer.Deferred()

        self.server = LeapIMAPServer(
            uuid=UUID, userid=USERID,
            contextFactory=self.serverCTX,
            soledad=self._soledad)

        self.client = SimpleClient(
            d_server_ready, contextFactory=self.clientCTX)

        theAccount = SoledadBackedAccount(
            USERID,
            soledad=self._soledad,
            memstore=memstore)
        d_account_ready = theAccount.callWhenReady(lambda r: None)
        LeapIMAPServer.theAccount = theAccount

        self.connected = defer.gatherResults(
            [d_server_ready, d_account_ready])

        # XXX FIXME --------------------------------------------
        # XXX this needs to be done differently,
        # have to be hooked on initialization callback instead.
        # in case we get something from previous tests...
        #for mb in self.server.theAccount.mailboxes:
            #self.server.theAccount.delete(mb)

        # email parser
        self.parser = parser.Parser()

    def tearDown(self):
        """
        tearDown method called after each test.

        Deletes all documents in the Index, and deletes
        instances of server and client.
        """
        try:
            self._soledad.close()
            os.environ["PATH"] = self.old_path
            os.environ["HOME"] = self.old_home
            # safety check
            assert 'leap_tests-' in self.tempdir
            shutil.rmtree(self.tempdir)
        except Exception:
            print "ERROR WHILE CLOSING SOLEDAD"

    def populateMessages(self):
        """
        Populates soledad instance with several simple messages
        """
        # XXX we should encapsulate this thru SoledadBackedAccount
        # instead.

        # XXX we also should put this in a mailbox!

        self._soledad.messages.add_msg('', subject="test1")
        self._soledad.messages.add_msg('', subject="test2")
        self._soledad.messages.add_msg('', subject="test3")
        # XXX should change Flags too
        self._soledad.messages.add_msg('', subject="test4")

    def delete_all_docs(self):
        """
        Deletes all the docs in the testing instance of the
        SoledadBackedAccount.
        """
        self.server.theAccount.deleteAllMessages(
            iknowhatiamdoing=True)

    def _cbStopClient(self, ignore):
        self.client.transport.loseConnection()

    def _ebGeneral(self, failure):
        self.client.transport.loseConnection()
        self.server.transport.loseConnection()
        # can we do something similar?
        # I guess this was ok with trial, but not in noseland...
        # log.err(failure, "Problem with %r" % (self.function,))
        raise failure.value
        # failure.trap(Exception)

    def loopback(self):
        return loopback.loopbackAsync(self.server, self.client)


