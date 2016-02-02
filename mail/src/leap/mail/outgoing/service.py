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

"""
OutgoingMail module.

The OutgoingMail class allows to send mail, and encrypts/signs it if needed.
"""

import os.path
import re
from StringIO import StringIO
from copy import deepcopy
from email.parser import Parser
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from OpenSSL import SSL

from twisted.mail import smtp
from twisted.internet import reactor
from twisted.internet import defer
from twisted.protocols.amp import ssl
from twisted.python import log

from leap.common.check import leap_assert_type, leap_assert
from leap.common.events import emit_async, catalog
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import KeyNotFound, KeyAddressMismatch
from leap.mail import __version__
from leap.mail import errors
from leap.mail.utils import validate_address
from leap.mail.rfc3156 import MultipartEncrypted
from leap.mail.rfc3156 import MultipartSigned
from leap.mail.rfc3156 import encode_base64_rec
from leap.mail.rfc3156 import RFC3156CompliantGenerator
from leap.mail.rfc3156 import PGPSignature
from leap.mail.rfc3156 import PGPEncrypted

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


def outgoingFactory(userid, keymanager, opts, check_cert=True):

    cert = unicode(opts.cert)
    key = unicode(opts.key)
    hostname = str(opts.hostname)
    port = opts.port

    if check_cert:
        if not os.path.isfile(cert):
            raise errors.ConfigurationError(
                'No valid SMTP certificate could be found for %s!' % userid)

    return OutgoingMail(str(userid), keymanager, cert, key, hostname, port)


class OutgoingMail(object):
    """
    Sends Outgoing Mail, encrypting and signing if needed.
    """

    def __init__(self, from_address, keymanager, cert, key, host, port):
        """
        Initialize the outgoing mail service.

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

        # XXX it can be a zope.proxy too
        # leap_assert_type(keymanager, KeyManager)

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
        fromaddr = self._from_address
        log.msg('Message sent from %s to %s' % (fromaddr, dest_addrstr))
        emit_async(catalog.SMTP_SEND_MESSAGE_SUCCESS,
                   fromaddr, dest_addrstr)

    def sendError(self, failure):
        """
        Callback for an unsuccessfull send.

        :param e: The result from the last errback.
        :type e: anything
        """
        # XXX: need to get the address from the exception to send signal
        # emit_async(catalog.SMTP_SEND_MESSAGE_ERROR, self._from_address,
        #   self._user.dest.addrstr)
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
            "",  # username is blank, no client auth here
            "",  # password is blank, no client auth here
            self._from_address,
            recipient.dest.addrstr,
            StringIO(msg),
            d,
            heloFallback=True,
            requireAuthentication=False,
            requireTransportSecurity=True)
        factory.domain = __version__
        emit_async(catalog.SMTP_SEND_MESSAGE_START,
                   self._from_address, recipient.dest.addrstr)
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
        origmsg = Parser().parsestr(raw)

        if origmsg.get_content_type() == 'multipart/encrypted':
            return defer.succeed((origmsg, recipient))

        from_address = validate_address(self._from_address)
        username, domain = from_address.split('@')
        to_address = validate_address(recipient.dest.addrstr)

        def maybe_encrypt_and_sign(message):
            d = self._encrypt_and_sign(message, to_address, from_address)
            d.addCallbacks(signal_encrypt_sign,
                           if_key_not_found_send_unencrypted,
                           errbackArgs=(message,))
            return d

        def signal_encrypt_sign(newmsg):
            emit_async(catalog.SMTP_END_ENCRYPT_AND_SIGN,
                       self._from_address,
                       "%s,%s" % (self._from_address, to_address))
            return newmsg, recipient

        def if_key_not_found_send_unencrypted(failure, message):
            failure.trap(KeyNotFound, KeyAddressMismatch)

            log.msg('Will send unencrypted message to %s.' % to_address)
            emit_async(catalog.SMTP_START_SIGN, self._from_address, to_address)
            d = self._sign(message, from_address)
            d.addCallback(signal_sign)
            return d

        def signal_sign(newmsg):
            emit_async(catalog.SMTP_END_SIGN, self._from_address)
            return newmsg, recipient

        log.msg("Will encrypt the message with %s and sign with %s."
                % (to_address, from_address))
        emit_async(catalog.SMTP_START_ENCRYPT_AND_SIGN,
                   self._from_address,
                   "%s,%s" % (self._from_address, to_address))
        d = self._maybe_attach_key(origmsg, from_address, to_address)
        d.addCallback(maybe_encrypt_and_sign)
        return d

    def _maybe_attach_key(self, origmsg, from_address, to_address):
        filename = "%s-email-key.asc" % (from_address,)

        def attach_if_address_hasnt_encrypted(to_key):
            # if the sign_used flag is true that means that we got an encrypted
            # email from this address, because we conly check signatures on
            # encrypted emails. In this case we don't attach.
            # XXX: this might not be true some time in the future
            if to_key.sign_used:
                return origmsg
            return get_key_and_attach(None)

        def get_key_and_attach(_):
            d = self._keymanager.get_key(from_address, OpenPGPKey,
                                         fetch_remote=False)
            d.addCallback(attach_key)
            return d

        def attach_key(from_key):
            msg = origmsg
            if not origmsg.is_multipart():
                msg = MIMEMultipart()
                for h, v in origmsg.items():
                    msg.add_header(h, v)
                msg.attach(MIMEText(origmsg.get_payload()))

            keymsg = MIMEApplication(from_key.key_data, _subtype='pgp-keys',
                                     _encoder=lambda x: x)
            keymsg.add_header('content-disposition', 'attachment',
                              filename=filename)
            msg.attach(keymsg)
            return msg

        d = self._keymanager.get_key(to_address, OpenPGPKey,
                                     fetch_remote=False)
        d.addCallbacks(attach_if_address_hasnt_encrypted, get_key_and_attach)
        d.addErrback(lambda _: origmsg)
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

    def _fix_headers(self, msg, newmsg, sign_address):
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

        :param msg: The original message.
        :type msg: email.message.Message
        :param newmsg: The new message being created.
        :type newmsg: email.message.Message
        :param sign_address: The address used to sign C{newmsg}
        :type sign_address: str

        :return: A Deferred with a touple:
                 (new Message with the unencrypted headers,
                  original Message with headers removed)
        :rtype: Deferred
        """
        origmsg = deepcopy(msg)
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
