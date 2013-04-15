import ConfigParser
import datetime
import os
from functools import partial

from xdg import BaseDirectory

from twisted.application import internet, service
from twisted.internet.protocol import ServerFactory
from twisted.mail import imap4
from twisted.python import log

from leap.common.check import leap_assert
from leap.mail.imap.server import SoledadBackedAccount
from leap.mail.imap.fetch import LeapIncomingMail
from leap.soledad import Soledad
#from leap.soledad import SoledadCrypto

# Some constants
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The port in which imap service will run
IMAP_PORT = 9930

# The period between succesive checks of the incoming mail
# queue (in seconds)
INCOMING_CHECK_PERIOD = 10
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


class LeapIMAPServer(imap4.IMAP4Server):
    """
    An IMAP4 Server with mailboxes backed by soledad
    """
    def __init__(self, *args, **kwargs):
        # pop extraneous arguments
        soledad = kwargs.pop('soledad', None)
        user = kwargs.pop('user', None)
        gpg = kwargs.pop('gpg', None)
        leap_assert(soledad, "need a soledad instance")
        leap_assert(user, "need a user in the initialization")

        # initialize imap server!
        imap4.IMAP4Server.__init__(self, *args, **kwargs)

        # we should initialize the account here,
        # but we move it to the factory so we can
        # populate the test account properly (and only once
        # per session)

        # theAccount = SoledadBackedAccount(
        #     user, soledad=soledad)

        # ---------------------------------
        # XXX pre-populate acct for tests!!
        # populate_test_account(theAccount)
        # ---------------------------------
        #self.theAccount = theAccount

    def lineReceived(self, line):
        log.msg('rcv: %s' % line)
        imap4.IMAP4Server.lineReceived(self, line)

    def authenticateLogin(self, username, password):
        # all is allowed so far. use realm instead
        return imap4.IAccount, self.theAccount, lambda: None


class IMAPAuthRealm(object):
    """
    dummy authentication realm
    """
    theAccount = None

    def requestAvatar(self, avatarId, mind, *interfaces):
        return imap4.IAccount, self.theAccount, lambda: None


class LeapIMAPFactory(ServerFactory):
    """
    Factory for a IMAP4 server with soledad remote sync and gpg-decryption
    capabilities.
    """

    def __init__(self, user, soledad, gpg=None):
        self._user = user
        self._soledad = soledad
        self._gpg = gpg

        theAccount = SoledadBackedAccount(
            user, soledad=soledad)

        # ---------------------------------
        # XXX pre-populate acct for tests!!
        # populate_test_account(theAccount)
        # ---------------------------------
        self.theAccount = theAccount

    def buildProtocol(self, addr):
        "Return a protocol suitable for the job."
        imapProtocol = LeapIMAPServer(
            user=self._user,
            soledad=self._soledad,
            gpg=self._gpg)
        imapProtocol.theAccount = self.theAccount
        imapProtocol.factory = self
        return imapProtocol

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# Let's rock...
#
# XXX initialize gpg

#from leap.mail.imap.tests import PUBLIC_KEY
#from leap.mail.imap.tests import PRIVATE_KEY
#from leap.soledad.util import GPGWrapper


def initialize_mailbox_soledad(user_uuid, soledad_pass, server_url,
                       	       server_pemfile, token):
    """
    Initializes soledad by hand

    :param user_uuid:
    :param soledad_pass:
    :param server_url:
    :param server_pemfile:
    :param token:

    :rtype: Soledad instance
    """
    #XXX do we need a separate instance for the mailbox db?

    base_config = BaseDirectory.xdg_config_home
    secret_path = os.path.join(
        base_config, "leap", "soledad", "%s.secret" % user_uuid)
    soledad_path = os.path.join(
        base_config, "leap", "soledad", "%s-mailbox.db" % user_uuid)


    _soledad = Soledad(
        user_uuid,
	soledad_pass,
        secret_path,
        soledad_path,
	server_url,
        server_pemfile,
        token,
        bootstrap=True)
    #_soledad._init_dirs()
    #_soledad._crypto = SoledadCrypto(_soledad)
    #_soledad._shared_db = None
    #_soledad._init_keys()
    #_soledad._init_db()

    return _soledad

'''
mail_sample = open('rfc822.message').read()
def populate_test_account(acct):
    """
    Populates inbox for testing purposes
    """
    print "populating test account!"
    inbox = acct.getMailbox('inbox')
    inbox.addMessage(mail_sample, ("\\Foo", "\\Recent",), date="Right now2")
'''

def incoming_check(fetcher):
    """
    Check incoming queue. To be called periodically.
    """
    #log.msg("checking incoming queue...")
    fetcher.fetch()


#######################################################################
# XXX STUBBED! We need to get this in the instantiation from the client

config = ConfigParser.ConfigParser()
config.read([os.path.expanduser('~/.config/leap/mail/mail.conf')])

userID = config.get('mail', 'address')
privkey = open(os.path.expanduser('~/.config/leap/mail/privkey')).read()
nickserver_url = ""

d = {}

for key in ('uid', 'passphrase', 'server', 'pemfile', 'token'):
    d[key] = config.get('mail', key)

soledad = initialize_mailbox_soledad(
    d['uid'],
    d['passphrase'],
    d['server'],
    d['pemfile'],
    d['token'])
gpg = None

# import the private key ---- should sync it from remote!
from leap.common.keymanager.openpgp import OpenPGPScheme
opgp = OpenPGPScheme(soledad)
opgp.put_ascii_key(privkey)

from leap.common.keymanager import KeyManager
keym = KeyManager(userID, nickserver_url, soledad, d['token'])

#import ipdb; ipdb.set_trace()


factory = LeapIMAPFactory(userID, soledad, gpg)

application = service.Application("LEAP IMAP4 Local Service")
imapService = internet.TCPServer(IMAP_PORT, factory)
imapService.setServiceParent(application)

fetcher = LeapIncomingMail(
    keym,
    d['uid'],
    d['passphrase'],
    d['server'],
    d['pemfile'],
    d['token'],
    factory.theAccount)


incoming_check_for_acct = partial(incoming_check, fetcher)
internet.TimerService(
    INCOMING_CHECK_PERIOD,
    incoming_check_for_acct).setServiceParent(application)
