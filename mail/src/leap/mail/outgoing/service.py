# -*- coding: utf-8 -*-
# outgoing/service.py
# Copyright (C) 2013-2015 LEAP
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
import re
from StringIO import StringIO
from email.parser import Parser
from email.mime.application import MIMEApplication

from OpenSSL import SSL

from twisted.mail import smtp
from twisted.internet import reactor
from twisted.internet import defer
from twisted.protocols.amp import ssl
from twisted.python import log

from leap.common.check import leap_assert_type, leap_assert
from leap.common.events import proto, signal
from leap.keymanager import KeyManager
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import KeyNotFound
from leap.mail import __version__
from leap.mail.utils import validate_address
from leap.mail.smtp.rfc3156 import MultipartEncrypted
from leap.mail.smtp.rfc3156 import MultipartSigned
from leap.mail.smtp.rfc3156 import encode_base64_rec
from leap.mail.smtp.rfc3156 import RFC3156CompliantGenerator
from leap.mail.smtp.rfc3156 import PGPSignature
from leap.mail.smtp.rfc3156 import PGPEncrypted

# TODO
# [ ] rename this module to something else, service should be the implementor
#     of IService


class SSLContextFactory(ssl.ClientContextFactory):
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def getContext(self):
        # FIXME -- we should use sslv23 to allow for tlsv1.2
        # and, if possible, explicitely disable sslv3 clientside.
        # Servers should avoid sslv3
        self.method = SSL.TLSv1_METHOD  # SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.use_certificate_file(self.cert)
        ctx.use_privatekey_file(self.key)
        return ctx


class OutgoingMail:
    """
    A service for handling encrypted outgoing mail.
    """

    FOOTER_STRING = "I prefer encrypted email"

    def __init__(self, from_address, keymanager, cert, key, host, port):
        """
        Initialize the mail service.

        :param from_address: The sender address.
        :type from_address: str
        :param keymanager: A KeyManager for retrieving recipient's keys.
        :type keymanager: leap.common.keymanager.KeyManager
        :param cert: The client certificate for SSL authentication.
        :type cert: str
        :param key: The client private key for SSL authentication.
        :type key: str
        :param host: The hostname of the remote SMTP server.
        :type host: str
        :param port: The port of the remote SMTP server.
        :type port: int
        """

        # assert params
        leap_assert_type(from_address, str)
        leap_assert('@' in from_address)
        leap_assert_type(keymanager, KeyManager)
        leap_assert_type(host, str)
        leap_assert(host != '')
        leap_assert_type(port, int)
        leap_assert(port is not 0)
        leap_assert_type(cert, unicode)
        leap_assert(cert != '')
        leap_assert_type(key, unicode)
        leap_assert(key != '')

        self._port = port
        self._host = host
        self._key = key
        self._cert = cert
        self._from_address = from_address
        self._keymanager = keymanager

    def send_message(self, raw, recipient):
        """
        Sends a message to a recipient. Maybe encrypts and signs.

        :param raw: The raw message
        :type raw: str
        :param recipient: The recipient for the message
        :type recipient: smtp.User
        :return: a deferred which delivers the message when fired
        """
        d = self._maybe_encrypt_and_sign(raw, recipient)
        d.addCallback(self._route_msg)
        d.addErrback(self.sendError)
        return d

    def sendSuccess(self, smtp_sender_result):
        """
        Callback for a successful send.

        :param smtp_sender_result: The result from the ESMTPSender from
                                   _route_msg
        :type smtp_sender_result: tuple(int, list(tuple))
        """
        dest_addrstr = smtp_sender_result[1][0][0]
        log.msg('Message sent to %s' % dest_addrstr)
        signal(proto.SMTP_SEND_MESSAGE_SUCCESS, dest_addrstr)

    def sendError(self, failure):
        """
        Callback for an unsuccessfull send.

        :param e: The result from the last errback.
        :type e: anything
        """
        # XXX: need to get the address from the exception to send signal
        # signal(proto.SMTP_SEND_MESSAGE_ERROR, self._user.dest.addrstr)
        err = failure.value
        log.err(err)
        raise err

    def _route_msg(self, encrypt_and_sign_result):
        """
        Sends the msg using the ESMTPSenderFactory.

        :param encrypt_and_sign_result: A tuple containing the 'maybe'
                                        encrypted message and the recipient
        :type encrypt_and_sign_result: tuple
        """
        message, recipient = encrypt_and_sign_result
        log.msg("Connecting to SMTP server %s:%s" % (self._host, self._port))
        msg = message.as_string(False)

        # we construct a defer to pass to the ESMTPSenderFactory
        d = defer.Deferred()
        d.addCallbacks(self.sendSuccess, self.sendError)
        # we don't pass an ssl context factory to the ESMTPSenderFactory
        # because ssl will be handled by reactor.connectSSL() below.
        factory = smtp.ESMTPSenderFactory(
            "",  # username is blank because client auth is done on SSL protocol level
            "",  # password is blank because client auth is done on SSL protocol level
            self._from_address,
            recipient.dest.addrstr,
            StringIO(msg),
            d,
            heloFallback=True,
            requireAuthentication=False,
            requireTransportSecurity=True)
        factory.domain = __version__
        signal(proto.SMTP_SEND_MESSAGE_START, recipient.dest.addrstr)
        reactor.connectSSL(
            self._host, self._port, factory,
            contextFactory=SSLContextFactory(self._cert, self._key))

    def _maybe_encrypt_and_sign(self, raw, recipient):
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

        :param raw: The raw message
        :type raw: str
        :param recipient: The recipient for the message
        :type: recipient: smtp.User

        :return: A Deferred that will be fired with a MIMEMultipart message
                 and the original recipient Message
        :rtype: Deferred
        """
        # pass if the original message's content-type is "multipart/encrypted"
        lines = raw.split('\r\n')
        origmsg = Parser().parsestr(raw)

        if origmsg.get_content_type() == 'multipart/encrypted':
            return defer.success((origmsg, recipient))

        from_address = validate_address(self._from_address)
        username, domain = from_address.split('@')
        to_address = validate_address(recipient.dest.addrstr)

        # add a nice footer to the outgoing message
        # XXX: footer will eventually optional or be removed
        if origmsg.get_content_type() == 'text/plain':
            lines.append('--')
            lines.append('%s - https://%s/key/%s' %
                         (self.FOOTER_STRING, domain, username))
            lines.append('')

        origmsg = Parser().parsestr('\r\n'.join(lines))

        def signal_encrypt_sign(newmsg):
            signal(proto.SMTP_END_ENCRYPT_AND_SIGN,
                   "%s,%s" % (self._from_address, to_address))
            return newmsg, recipient

        def signal_sign(newmsg):
            signal(proto.SMTP_END_SIGN, self._from_address)
            return newmsg, recipient

        def if_key_not_found_send_unencrypted(failure):
            if failure.check(KeyNotFound):
                log.msg('Will send unencrypted message to %s.' % to_address)
                signal(proto.SMTP_START_SIGN, self._from_address)
                d = self._sign(origmsg, from_address)
                d.addCallback(signal_sign)
                return d
            else:
                return failure

        log.msg("Will encrypt the message with %s and sign with %s."
                % (to_address, from_address))
        signal(proto.SMTP_START_ENCRYPT_AND_SIGN,
               "%s,%s" % (self._from_address, to_address))
        d = self._encrypt_and_sign(origmsg, to_address, from_address)
        d.addCallbacks(signal_encrypt_sign, if_key_not_found_send_unencrypted)
        return d

    def _encrypt_and_sign(self, origmsg, encrypt_address, sign_address):
        """
        Create an RFC 3156 compliang PGP encrypted and signed message using
        C{encrypt_address} to encrypt and C{sign_address} to sign.

        :param origmsg: The original message
        :type origmsg: email.message.Message
        :param encrypt_address: The address used to encrypt the message.
        :type encrypt_address: str
        :param sign_address: The address used to sign the message.
        :type sign_address: str

        :return: A Deferred with the MultipartEncrypted message
        :rtype: Deferred
        """
        # create new multipart/encrypted message with 'pgp-encrypted' protocol

        def encrypt(res):
            newmsg, origmsg = res
            d = self._keymanager.encrypt(
                origmsg.as_string(unixfrom=False),
                encrypt_address, OpenPGPKey, sign=sign_address)
            d.addCallback(lambda encstr: (newmsg, encstr))
            return d

        def create_encrypted_message(res):
            newmsg, encstr = res
            encmsg = MIMEApplication(
                encstr, _subtype='octet-stream', _encoder=lambda x: x)
            encmsg.add_header('content-disposition', 'attachment',
                              filename='msg.asc')
            # create meta message
            metamsg = PGPEncrypted()
            metamsg.add_header('Content-Disposition', 'attachment')
            # attach pgp message parts to new message
            newmsg.attach(metamsg)
            newmsg.attach(encmsg)
            return newmsg

        d = self._fix_headers(
            origmsg,
            MultipartEncrypted('application/pgp-encrypted'),
            sign_address)
        d.addCallback(encrypt)
        d.addCallback(create_encrypted_message)
        return d

    def _sign(self, origmsg, sign_address):
        """
        Create an RFC 3156 compliant PGP signed MIME message using
        C{sign_address}.

        :param origmsg: The original message
        :type origmsg: email.message.Message
        :param sign_address: The address used to sign the message.
        :type sign_address: str

        :return: A Deferred with the MultipartSigned message.
        :rtype: Deferred
        """
        # apply base64 content-transfer-encoding
        encode_base64_rec(origmsg)
        # get message text with headers and replace \n for \r\n
        fp = StringIO()
        g = RFC3156CompliantGenerator(
            fp, mangle_from_=False, maxheaderlen=76)
        g.flatten(origmsg)
        msgtext = re.sub('\r?\n', '\r\n', fp.getvalue())
        # make sure signed message ends with \r\n as per OpenPGP stantard.
        if origmsg.is_multipart():
            if not msgtext.endswith("\r\n"):
                msgtext += "\r\n"

        def create_signed_message(res):
            (msg, _), signature = res
            sigmsg = PGPSignature(signature)
            # attach original message and signature to new message
            msg.attach(origmsg)
            msg.attach(sigmsg)
            return msg

        dh = self._fix_headers(
            origmsg,
            MultipartSigned('application/pgp-signature', 'pgp-sha512'),
            sign_address)
        ds = self._keymanager.sign(
            msgtext, sign_address, OpenPGPKey, digest_algo='SHA512',
            clearsign=False, detach=True, binary=False)
        d = defer.gatherResults([dh, ds])
        d.addCallback(create_signed_message)
        return d

    def _fix_headers(self, origmsg, newmsg, sign_address):
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
        :param sign_address: The address used to sign C{newmsg}
        :type sign_address: str

        :return: A Deferred with a touple:
                 (new Message with the unencrypted headers,
                  original Message with headers removed)
        :rtype: Deferred
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
            del (origmsg[hkey])
        # add a new message-id to newmsg
        newmsg.add_header('Message-Id', smtp.messageid())
        # delete user-agent from origmsg
        del (origmsg['user-agent'])

        def add_openpgp_header(signkey):
            username, domain = sign_address.split('@')
            newmsg.add_header(
                'OpenPGP', 'id=%s' % signkey.key_id,
                url='https://%s/key/%s' % (domain, username),
                preference='signencrypt')
            return newmsg, origmsg

        d = self._keymanager.get_key(sign_address, OpenPGPKey, private=True)
        d.addCallback(add_openpgp_header)
        return d
