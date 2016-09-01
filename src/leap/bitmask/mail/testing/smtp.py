from twisted.mail import smtp

from leap.bitmask.mail.smtp.gateway import SMTPFactory, LOCAL_FQDN
from leap.bitmask.mail.smtp.gateway import SMTPDelivery
from leap.bitmask.mail.outgoing.service import outgoingFactory

TEST_USER = u'anotheruser@leap.se'


class UnauthenticatedSMTPServer(smtp.SMTP):

    encrypted_only = False

    def __init__(self, soledads, keyms, opts, encrypted_only=False):
        smtp.SMTP.__init__(self)

        userid = TEST_USER
        keym = keyms[userid]

        class Opts:
            cert = '/tmp/cert'
            key = '/tmp/cert'
            hostname = 'remote'
            port = 666

        outgoing = outgoingFactory(
            userid, keym, Opts, check_cert=False)
        avatar = SMTPDelivery(userid, keym, encrypted_only, outgoing)
        self.delivery = avatar

    def validateFrom(self, helo, origin):
        return origin


class UnauthenticatedSMTPFactory(SMTPFactory):
    """
    A Factory that produces a SMTP server that does not authenticate user.
    Only for tests!
    """
    protocol = UnauthenticatedSMTPServer
    domain = LOCAL_FQDN
    encrypted_only = False


def getSMTPFactory(soledad_s, keymanager_s, sendmail_opts,
                   encrypted_only=False):
    factory = UnauthenticatedSMTPFactory
    factory.encrypted_only = encrypted_only
    proto = factory(
        soledad_s, keymanager_s, sendmail_opts).buildProtocol(('127.0.0.1', 0))
    return proto
