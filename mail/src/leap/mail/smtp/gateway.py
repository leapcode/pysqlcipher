# -*- coding: utf-8 -*-
# gateway.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
LEAP SMTP encrypted gateway.

The following classes comprise the SMTP gateway service:

    * SMTPFactory - A twisted.internet.protocol.ServerFactory that provides
      the SMTPDelivery protocol.
    * SMTPDelivery - A twisted.mail.smtp.IMessageDelivery implementation. It
      knows how to validate sender and receiver of messages and it generates
      an EncryptedMessage for each recipient.
    * SSLContextFactory - Contains the relevant ssl information for the
      connection.
    * EncryptedMessage - An implementation of twisted.mail.smtp.IMessage that
      knows how to encrypt/sign itself before sending.


"""
import re
from StringIO import StringIO
from email.Header import Header
from email.utils import parseaddr
from email.parser import Parser
from email.mime.application import MIMEApplication

from zope.interface import implements
from OpenSSL import SSL
from twisted.mail import smtp
from twisted.internet.protocol import ServerFactory
from twisted.internet import reactor, ssl
from twisted.internet import defer
from twisted.internet.threads import deferToThread
from twisted.python import log

from leap.common.check import leap_assert, leap_assert_type
from leap.common.events import proto, signal
from leap.keymanager import KeyManager
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import KeyNotFound
from leap.mail.smtp.rfc3156 import (
    MultipartSigned,
    MultipartEncrypted,
    PGPEncrypted,
    PGPSignature,
    RFC3156CompliantGenerator,
    encode_base64_rec,
)

# replace email generator with a RFC 3156 compliant one.
from email import generator
generator.Generator = RFC3156CompliantGenerator


#
# Helper utilities
#

LOCAL_FQDN = "bitmask.local"


def validate_address(address):
    """
    Validate C{address} as defined in RFC 2822.

    :param address: The address to be validated.
    :type address: str

    @return: A valid address.
    @rtype: str

    @raise smtp.SMTPBadRcpt: Raised if C{address} is invalid.
    """
    leap_assert_type(address, str)
    # in the following, the address is parsed as described in RFC 2822 and
    # ('', '') is returned if the parse fails.
    _, address = parseaddr(address)
    if address == '':
        raise smtp.SMTPBadRcpt(address)
    return address


#
# SMTPFactory
#

class SMTPHeloLocalhost(smtp.SMTP):
    """
    An SMTP class that ensures a proper FQDN
    for localhost.

    This avoids a problem in which unproperly configured providers
    would complain about the helo not being a fqdn.
    """

    def __init__(self, *args):
        smtp.SMTP.__init__(self, *args)
        self.host = LOCAL_FQDN


class SMTPFactory(ServerFactory):
    """
    Factory for an SMTP server with encrypted gatewaying capabilities.
    """
    domain = LOCAL_FQDN

    def __init__(self, userid, keymanager, host, port, cert, key,
                 encrypted_only):
        """
        Initialize the SMTP factory.

        :param userid: The user currently logged in
        :type userid: unicode
        :param keymanager: A KeyManager for retrieving recipient's keys.
        :type keymanager: leap.common.keymanager.KeyManager
        :param host: The hostname of the remote SMTP server.
        :type host: str
        :param port: The port of the remote SMTP server.
        :type port: int
        :param cert: The client certificate for authentication.
        :type cert: str
        :param key: The client key for authentication.
        :type key: str
        :param encrypted_only: Whether the SMTP gateway should send unencrypted
                               mail or not.
        :type encrypted_only: bool
        """
        # assert params
        leap_assert_type(keymanager, KeyManager)
        leap_assert_type(host, str)
        leap_assert(host != '')
        leap_assert_type(port, int)
        leap_assert(port is not 0)
        leap_assert_type(cert, unicode)
        leap_assert(cert != '')
        leap_assert_type(key, unicode)
        leap_assert(key != '')
        leap_assert_type(encrypted_only, bool)
        # and store them
        self._userid = userid
        self._km = keymanager
        self._host = host
        self._port = port
        self._cert = cert
        self._key = key
        self._encrypted_only = encrypted_only

    def buildProtocol(self, addr):
        """
        Return a protocol suitable for the job.

        :param addr: An address, e.g. a TCP (host, port).
        :type addr:  twisted.internet.interfaces.IAddress

        @return: The protocol.
        @rtype: SMTPDelivery
        """
        smtpProtocol = SMTPHeloLocalhost(SMTPDelivery(
            self._userid, self._km, self._host, self._port, self._cert,
            self._key, self._encrypted_only))
        smtpProtocol.factory = self
        return smtpProtocol


#
# SMTPDelivery
#

class SMTPDelivery(object):
    """
    Validate email addresses and handle message delivery.
    """

    implements(smtp.IMessageDelivery)

    def __init__(self, userid, keymanager, host, port, cert, key,
                 encrypted_only):
        """
        Initialize the SMTP delivery object.

        :param userid: The user currently logged in
        :type userid: unicode
        :param keymanager: A KeyManager for retrieving recipient's keys.
        :type keymanager: leap.common.keymanager.KeyManager
        :param host: The hostname of the remote SMTP server.
        :type host: str
        :param port: The port of the remote SMTP server.
        :type port: int
        :param cert: The client certificate for authentication.
        :type cert: str
        :param key: The client key for authentication.
        :type key: str
        :param encrypted_only: Whether the SMTP gateway should send unencrypted
                               mail or not.
        :type encrypted_only: bool
        """
        self._userid = userid
        self._km = keymanager
        self._host = host
        self._port = port
        self._cert = cert
        self._key = key
        self._encrypted_only = encrypted_only
        self._origin = None

    def receivedHeader(self, helo, origin, recipients):
        """
        Generate the 'Received:' header for a message.

        :param helo: The argument to the HELO command and the client's IP
            address.
        :type helo: (str, str)
        :param origin: The address the message is from.
        :type origin: twisted.mail.smtp.Address
        :param recipients: A list of the addresses for which this message is
            bound.
        :type: list of twisted.mail.smtp.User

        @return: The full "Received" header string.
        :type: str
        """
        myHostname, clientIP = helo
        headerValue = "by bitmask.local from %s with ESMTP ; %s" % (
            clientIP, smtp.rfc822date())
        # email.Header.Header used for automatic wrapping of long lines
        return "Received: %s" % Header(s=headerValue, header_name='Received')

    def validateTo(self, user):
        """
        Validate the address of C{user}, a recipient of the message.

        This method is called once for each recipient and validates the
        C{user}'s address against the RFC 2822 definition. If the
        configuration option ENCRYPTED_ONLY_KEY is True, it also asserts the
        existence of the user's key.

        In the end, it returns an encrypted message object that is able to
        send itself to the C{user}'s address.

        :param user: The user whose address we wish to validate.
        :type: twisted.mail.smtp.User

        @return: A Deferred which becomes, or a callable which takes no
            arguments and returns an object implementing IMessage. This will
            be called and the returned object used to deliver the message when
            it arrives.
        @rtype: no-argument callable

        @raise SMTPBadRcpt: Raised if messages to the address are not to be
            accepted.
        """
        # try to find recipient's public key
        try:
            address = validate_address(user.dest.addrstr)
            # verify if recipient key is available in keyring
            self._km.get_key(address, OpenPGPKey)  # might raise KeyNotFound
            log.msg("Accepting mail for %s..." % user.dest.addrstr)
            signal(proto.SMTP_RECIPIENT_ACCEPTED_ENCRYPTED, user.dest.addrstr)
        except KeyNotFound:
            # if key was not found, check config to see if will send anyway.
            if self._encrypted_only:
                signal(proto.SMTP_RECIPIENT_REJECTED, user.dest.addrstr)
                raise smtp.SMTPBadRcpt(user.dest.addrstr)
            log.msg("Warning: will send an unencrypted message (because "
                    "encrypted_only' is set to False).")
            signal(
                proto.SMTP_RECIPIENT_ACCEPTED_UNENCRYPTED, user.dest.addrstr)
        return lambda: EncryptedMessage(
            self._origin, user, self._km, self._host, self._port, self._cert,
            self._key)

    def validateFrom(self, helo, origin):
        """
        Validate the address from which the message originates.

        :param helo: The argument to the HELO command and the client's IP
            address.
        :type: (str, str)
        :param origin: The address the message is from.
        :type origin: twisted.mail.smtp.Address

        @return: origin or a Deferred whose callback will be passed origin.
        @rtype: Deferred or Address

        @raise twisted.mail.smtp.SMTPBadSender: Raised if messages from this
            address are not to be accepted.
        """
        # accept mail from anywhere. To reject an address, raise
        # smtp.SMTPBadSender here.
        if str(origin) != str(self._userid):
            log.msg("Rejecting sender {0}, expected {1}".format(origin,
                                                                self._userid))
            raise smtp.SMTPBadSender(origin)
        self._origin = origin
        return origin


#
# EncryptedMessage
#

class SSLContextFactory(ssl.ClientContextFactory):
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def getContext(self):
        self.method = SSL.TLSv1_METHOD  # SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.use_certificate_file(self.cert)
        ctx.use_privatekey_file(self.key)
        return ctx


class EncryptedMessage(object):
    """
    Receive plaintext from client, encrypt it and send message to a
    recipient.
    """
    implements(smtp.IMessage)

    def __init__(self, fromAddress, user, keymanager, host, port, cert, key):
        """
        Initialize the encrypted message.

        :param fromAddress: The address of the sender.
        :type fromAddress: twisted.mail.smtp.Address
        :param user: The recipient of this message.
        :type user: twisted.mail.smtp.User
        :param keymanager: A KeyManager for retrieving recipient's keys.
        :type keymanager: leap.common.keymanager.KeyManager
        :param host: The hostname of the remote SMTP server.
        :type host: str
        :param port: The port of the remote SMTP server.
        :type port: int
        :param cert: The client certificate for authentication.
        :type cert: str
        :param key: The client key for authentication.
        :type key: str
        """
        # assert params
        leap_assert_type(user, smtp.User)
        leap_assert_type(keymanager, KeyManager)
        # and store them
        self._fromAddress = fromAddress
        self._user = user
        self._km = keymanager
        self._host = host
        self._port = port
        self._cert = cert
        self._key = key
        # initialize list for message's lines
        self.lines = []

    #
    # methods from smtp.IMessage
    #

    def lineReceived(self, line):
        """
        Handle another line.

        :param line: The received line.
        :type line: str
        """
        self.lines.append(line)

    def eomReceived(self):
        """
        Handle end of message.

        This method will encrypt and send the message.

        :returns: a deferred
        """
        log.msg("Message data complete.")
        self.lines.append('')  # add a trailing newline
        d = deferToThread(self._maybe_encrypt_and_sign)
        d.addCallbacks(self.sendMessage, self.skipNoKeyErrBack)
        return d

    def connectionLost(self):
        """
        Log an error when the connection is lost.
        """
        log.msg("Connection lost unexpectedly!")
        log.err()
        signal(proto.SMTP_CONNECTION_LOST, self._user.dest.addrstr)
        # unexpected loss of connection; don't save
        self.lines = []

    # ends IMessage implementation

    def skipNoKeyErrBack(self, failure):
        """
        Errback that ignores a KeyNotFound

        :param failure: the failure
        :type Failure: Failure
        """
        err = failure.value
        if failure.check(KeyNotFound):
            pass
        else:
            raise err

    def parseMessage(self):
        """
        Separate message headers from body.
        """
        parser = Parser()
        return parser.parsestr('\r\n'.join(self.lines))

    def sendQueued(self, r):
        """
        Callback for the queued message.

        :param r: The result from the last previous callback in the chain.
        :type r: anything
        """
        log.msg(r)

    def sendSuccess(self, r):
        """
        Callback for a successful send.

        :param r: The result from the last previous callback in the chain.
        :type r: anything
        """
        log.msg(r)
        signal(proto.SMTP_SEND_MESSAGE_SUCCESS, self._user.dest.addrstr)

    def sendError(self, failure):
        """
        Callback for an unsuccessfull send.

        :param e: The result from the last errback.
        :type e: anything
        """
        signal(proto.SMTP_SEND_MESSAGE_ERROR, self._user.dest.addrstr)
        err = failure.value
        log.err(err)
        raise err

    def sendMessage(self, *args):
        """
        Sends the message.

        :return: A deferred with callbacks for error and success of this
                 #message send.
        :rtype: twisted.internet.defer.Deferred
        """
        d = deferToThread(self._route_msg)
        d.addCallbacks(self.sendQueued, self.sendError)
        return

    def _route_msg(self):
        """
        Sends the msg using the ESMTPSenderFactory.
        """
        log.msg("Connecting to SMTP server %s:%s" % (self._host, self._port))
        msg = self._msg.as_string(False)

        # we construct a defer to pass to the ESMTPSenderFactory
        d = defer.Deferred()
        d.addCallbacks(self.sendSuccess, self.sendError)
        # we don't pass an ssl context factory to the ESMTPSenderFactory
        # because ssl will be handled by reactor.connectSSL() below.
        factory = smtp.ESMTPSenderFactory(
            "",  # username is blank because server does not use auth.
            "",  # password is blank because server does not use auth.
            self._fromAddress.addrstr,
            self._user.dest.addrstr,
            StringIO(msg),
            d,
            heloFallback=True,
            requireAuthentication=False,
            requireTransportSecurity=True)
        factory.domain = LOCAL_FQDN
        signal(proto.SMTP_SEND_MESSAGE_START, self._user.dest.addrstr)
        reactor.connectSSL(
            self._host, self._port, factory,
            contextFactory=SSLContextFactory(self._cert, self._key))

    #
    # encryption methods
    #

    def _encrypt_and_sign(self, pubkey, signkey):
        """
        Create an RFC 3156 compliang PGP encrypted and signed message using
        C{pubkey} to encrypt and C{signkey} to sign.

        :param pubkey: The public key used to encrypt the message.
        :type pubkey: OpenPGPKey
        :param signkey: The private key used to sign the message.
        :type signkey: OpenPGPKey
        """
        # create new multipart/encrypted message with 'pgp-encrypted' protocol
        newmsg = MultipartEncrypted('application/pgp-encrypted')
        # move (almost) all headers from original message to the new message
        self._fix_headers(self._origmsg, newmsg, signkey)
        # create 'application/octet-stream' encrypted message
        encmsg = MIMEApplication(
            self._km.encrypt(self._origmsg.as_string(unixfrom=False), pubkey,
                             sign=signkey),
            _subtype='octet-stream', _encoder=lambda x: x)
        encmsg.add_header('content-disposition', 'attachment',
                          filename='msg.asc')
        # create meta message
        metamsg = PGPEncrypted()
        metamsg.add_header('Content-Disposition', 'attachment')
        # attach pgp message parts to new message
        newmsg.attach(metamsg)
        newmsg.attach(encmsg)
        self._msg = newmsg

    def _sign(self, signkey):
        """
        Create an RFC 3156 compliant PGP signed MIME message using C{signkey}.

        :param signkey: The private key used to sign the message.
        :type signkey: leap.common.keymanager.openpgp.OpenPGPKey
        """
        # create new multipart/signed message
        newmsg = MultipartSigned('application/pgp-signature', 'pgp-sha512')
        # move (almost) all headers from original message to the new message
        self._fix_headers(self._origmsg, newmsg, signkey)
        # apply base64 content-transfer-encoding
        encode_base64_rec(self._origmsg)
        # get message text with headers and replace \n for \r\n
        fp = StringIO()
        g = RFC3156CompliantGenerator(
            fp, mangle_from_=False, maxheaderlen=76)
        g.flatten(self._origmsg)
        msgtext = re.sub('\r?\n', '\r\n', fp.getvalue())
        # make sure signed message ends with \r\n as per OpenPGP stantard.
        if self._origmsg.is_multipart():
            if not msgtext.endswith("\r\n"):
                msgtext += "\r\n"
        # calculate signature
        signature = self._km.sign(msgtext, signkey, digest_algo='SHA512',
                                  clearsign=False, detach=True, binary=False)
        sigmsg = PGPSignature(signature)
        # attach original message and signature to new message
        newmsg.attach(self._origmsg)
        newmsg.attach(sigmsg)
        self._msg = newmsg

    def _maybe_encrypt_and_sign(self):
        """
        Attempt to encrypt and sign the outgoing message.

        The behaviour of this method depends on:

            1. the original message's content-type, and
            2. the availability of the recipient's public key.

        If the original message's content-type is "multipart/encrypted", then
        the original message is not altered. For any other content-type, the
        method attempts to fetch the recipient's public key. If the
        recipient's public key is available, the message is encrypted and
        signed; otherwise it is only signed.

        Note that, if the C{encrypted_only} configuration is set to True and
        the recipient's public key is not available, then the recipient
        address would have been rejected in SMTPDelivery.validateTo().

        The following table summarizes the overall behaviour of the gateway:

        +---------------------------------------------------+----------------+
        | content-type        | rcpt pubkey | enforce encr. | action         |
        +---------------------+-------------+---------------+----------------+
        | multipart/encrypted | any         | any           | pass           |
        | other               | available   | any           | encrypt + sign |
        | other               | unavailable | yes           | reject         |
        | other               | unavailable | no            | sign           |
        +---------------------+-------------+---------------+----------------+
        """
        # pass if the original message's content-type is "multipart/encrypted"
        self._origmsg = self.parseMessage()
        if self._origmsg.get_content_type() == 'multipart/encrypted':
            self._msg = self._origmsg
            return

        from_address = validate_address(self._fromAddress.addrstr)
        signkey = self._km.get_key(from_address, OpenPGPKey, private=True)
        log.msg("Will sign the message with %s." % signkey.fingerprint)
        to_address = validate_address(self._user.dest.addrstr)
        try:
            # try to get the recipient pubkey
            pubkey = self._km.get_key(to_address, OpenPGPKey)
            log.msg("Will encrypt the message to %s." % pubkey.fingerprint)
            signal(proto.SMTP_START_ENCRYPT_AND_SIGN,
                   "%s,%s" % (self._fromAddress.addrstr, to_address))
            self._encrypt_and_sign(pubkey, signkey)
            signal(proto.SMTP_END_ENCRYPT_AND_SIGN,
                   "%s,%s" % (self._fromAddress.addrstr, to_address))
        except KeyNotFound:
            # at this point we _can_ send unencrypted mail, because if the
            # configuration said the opposite the address would have been
            # rejected in SMTPDelivery.validateTo().
            log.msg('Will send unencrypted message to %s.' % to_address)
            signal(proto.SMTP_START_SIGN, self._fromAddress.addrstr)
            self._sign(signkey)
            signal(proto.SMTP_END_SIGN, self._fromAddress.addrstr)

    def _fix_headers(self, origmsg, newmsg, signkey):
        """
        Move some headers from C{origmsg} to C{newmsg}, delete unwanted
        headers from C{origmsg} and add new headers to C{newms}.

        Outgoing messages are either encrypted and signed or just signed
        before being sent. Because of that, they are packed inside new
        messages and some manipulation has to be made on their headers.

        Allowed headers for passing through:

            - From
            - Date
            - To
            - Subject
            - Reply-To
            - References
            - In-Reply-To
            - Cc

        Headers to be added:

            - Message-ID (i.e. should not use origmsg's Message-Id)
            - Received (this is added automatically by twisted smtp API)
            - OpenPGP (see #4447)

        Headers to be deleted:

            - User-Agent

        :param origmsg: The original message.
        :type origmsg: email.message.Message
        :param newmsg: The new message being created.
        :type newmsg: email.message.Message
        :param signkey: The key used to sign C{newmsg}
        :type signkey: OpenPGPKey
        """
        # move headers from origmsg to newmsg
        headers = origmsg.items()
        passthrough = [
            'from', 'date', 'to', 'subject', 'reply-to', 'references',
            'in-reply-to', 'cc'
        ]
        headers = filter(lambda x: x[0].lower() in passthrough, headers)
        for hkey, hval in headers:
            newmsg.add_header(hkey, hval)
            del(origmsg[hkey])
        # add a new message-id to newmsg
        newmsg.add_header('Message-Id', smtp.messageid())
        # add openpgp header to newmsg
        username, domain = signkey.address.split('@')
        newmsg.add_header(
            'OpenPGP', 'id=%s' % signkey.key_id,
            url='https://%s/openpgp/%s' % (domain, username))
        # delete user-agent from origmsg
        del(origmsg['user-agent'])
