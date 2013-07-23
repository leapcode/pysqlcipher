# -*- coding: utf-8 -*-
# smtprelay.py
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
LEAP SMTP encrypted relay.
"""

import re
import os
import tempfile


from zope.interface import implements
from StringIO import StringIO
from twisted.mail import smtp
from twisted.internet.protocol import ServerFactory
from twisted.internet import reactor
from twisted.internet import defer
from twisted.python import log
from email.Header import Header
from email.utils import parseaddr
from email.parser import Parser


from leap.common.check import leap_assert, leap_assert_type
from leap.keymanager import KeyManager
from leap.keymanager.openpgp import (
    OpenPGPKey,
    encrypt_asym,
    sign,
)
from leap.keymanager.errors import KeyNotFound


#
# Exceptions
#

class MalformedConfig(Exception):
    """
    Raised when the configuration dictionary passed as parameter is malformed.
    """
    pass


#
# Helper utilities
#

HOST_KEY = 'host'
PORT_KEY = 'port'
USERNAME_KEY = 'username'
PASSWORD_KEY = 'password'
ENCRYPTED_ONLY_KEY = 'encrypted_only'


def assert_config_structure(config):
    """
    Assert that C{config} is a dict with the following structure:

        {
            HOST_KEY: '<str>',
            PORT_KEY: <int>,
            USERNAME_KEY: '<str>',
            PASSWORD_KEY: '<str>',
            ENCRYPTED_ONLY_KEY: <bool>,
        }

    @param config: The dictionary to check.
    @type config: dict
    """
    # assert smtp config structure is valid
    leap_assert_type(config, dict)
    leap_assert(HOST_KEY in config)
    leap_assert_type(config[HOST_KEY], str)
    leap_assert(PORT_KEY in config)
    leap_assert_type(config[PORT_KEY], int)
    leap_assert(USERNAME_KEY in config)
    leap_assert_type(config[USERNAME_KEY], str)
    leap_assert(PASSWORD_KEY in config)
    leap_assert_type(config[PASSWORD_KEY], str)
    leap_assert(ENCRYPTED_ONLY_KEY in config)
    leap_assert_type(config[ENCRYPTED_ONLY_KEY], bool)
    # assert received params are not empty
    leap_assert(config[HOST_KEY] != '')
    leap_assert(config[PORT_KEY] is not 0)
    leap_assert(config[USERNAME_KEY] != '')
    leap_assert(config[PASSWORD_KEY] != '')


def validate_address(address):
    """
    Validate C{address} as defined in RFC 2822.

    @param address: The address to be validated.
    @type address: str

    @return: A valid address.
    @rtype: str

    @raise smtp.SMTPBadRcpt: Raised if C{address} is invalid.
    """
    leap_assert_type(address, str)
    # the following parses the address as described in RFC 2822 and
    # returns ('', '') if the parse fails.
    _, address = parseaddr(address)
    if address == '':
        raise smtp.SMTPBadRcpt(address)
    return address


#
# SMTPFactory
#

class SMTPFactory(ServerFactory):
    """
    Factory for an SMTP server with encrypted relaying capabilities.
    """

    def __init__(self, keymanager, config):
        """
        Initialize the SMTP factory.

        @param keymanager: A KeyManager for retrieving recipient's keys.
        @type keymanager: leap.common.keymanager.KeyManager
        @param config: A dictionary with smtp configuration. Should have
            the following structure:
                {
                    HOST_KEY: '<str>',
                    PORT_KEY: <int>,
                    USERNAME_KEY: '<str>',
                    PASSWORD_KEY: '<str>',
                    ENCRYPTED_ONLY_KEY: <bool>,
                }
        @type config: dict
        """
        # assert params
        leap_assert_type(keymanager, KeyManager)
        assert_config_structure(config)
        # and store them
        self._km = keymanager
        self._config = config

    def buildProtocol(self, addr):
        """
        Return a protocol suitable for the job.

        @param addr: An address, e.g. a TCP (host, port).
        @type addr:  twisted.internet.interfaces.IAddress

        @return: The protocol.
        @rtype: SMTPDelivery
        """
        # If needed, we might use ESMTPDelivery here instead.
        smtpProtocol = smtp.SMTP(SMTPDelivery(self._km, self._config))
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

    def __init__(self, keymanager, config):
        """
        Initialize the SMTP delivery object.

        @param keymanager: A KeyManager for retrieving recipient's keys.
        @type keymanager: leap.common.keymanager.KeyManager
        @param config: A dictionary with smtp configuration. Should have
            the following structure:
                {
                    HOST_KEY: '<str>',
                    PORT_KEY: <int>,
                    USERNAME_KEY: '<str>',
                    PASSWORD_KEY: '<str>',
                    ENCRYPTED_ONLY_KEY: <bool>,
                }
        @type config: dict
        """
        # assert params
        leap_assert_type(keymanager, KeyManager)
        assert_config_structure(config)
        # and store them
        self._km = keymanager
        self._config = config
        self._origin = None

    def receivedHeader(self, helo, origin, recipients):
        """
        Generate the 'Received:' header for a message.

        @param helo: The argument to the HELO command and the client's IP
            address.
        @type helo: (str, str)
        @param origin: The address the message is from.
        @type origin: twisted.mail.smtp.Address
        @param recipients: A list of the addresses for which this message is
            bound.
        @type: list of twisted.mail.smtp.User

        @return: The full "Received" header string.
        @type: str
        """
        myHostname, clientIP = helo
        headerValue = "by %s from %s with ESMTP ; %s" % (
            myHostname, clientIP, smtp.rfc822date())
        # email.Header.Header used for automatic wrapping of long lines
        return "Received: %s" % Header(headerValue)

    def validateTo(self, user):
        """
        Validate the address of C{user}, a recipient of the message.

        This method is called once for each recipient and validates the
        C{user}'s address against the RFC 2822 definition. If the
        configuration option ENCRYPTED_ONLY_KEY is True, it also asserts the
        existence of the user's key.

        In the end, it returns an encrypted message object that is able to
        send itself to the C{user}'s address.

        @param user: The user whose address we wish to validate.
        @type: twisted.mail.smtp.User

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
            pubkey = self._km.get_key(address, OpenPGPKey)
            log.msg("Accepting mail for %s..." % user.dest)
        except KeyNotFound:
            # if key was not found, check config to see if will send anyway.
            if self._config[ENCRYPTED_ONLY_KEY]:
                raise smtp.SMTPBadRcpt(user.dest.addrstr)
            log.msg("Warning: will send an unencrypted message (because "
                    "encrypted_only' is set to False).")
        return lambda: EncryptedMessage(
            self._origin, user, self._km, self._config)

    def validateFrom(self, helo, origin):
        """
        Validate the address from which the message originates.

        @param helo: The argument to the HELO command and the client's IP
            address.
        @type: (str, str)
        @param origin: The address the message is from.
        @type origin: twisted.mail.smtp.Address

        @return: origin or a Deferred whose callback will be passed origin.
        @rtype: Deferred or Address

        @raise twisted.mail.smtp.SMTPBadSender: Raised if messages from this
            address are not to be accepted.
        """
        # accept mail from anywhere. To reject an address, raise
        # smtp.SMTPBadSender here.
        self._origin = origin
        return origin


#
# EncryptedMessage
#

class EncryptedMessage(object):
    """
    Receive plaintext from client, encrypt it and send message to a
    recipient.
    """
    implements(smtp.IMessage)

    def __init__(self, fromAddress, user, keymanager, config):
        """
        Initialize the encrypted message.

        @param fromAddress: The address of the sender.
        @type fromAddress: twisted.mail.smtp.Address
        @param user: The recipient of this message.
        @type user: twisted.mail.smtp.User
        @param keymanager: A KeyManager for retrieving recipient's keys.
        @type keymanager: leap.common.keymanager.KeyManager
        @param config: A dictionary with smtp configuration. Should have
            the following structure:
                {
                    HOST_KEY: '<str>',
                    PORT_KEY: <int>,
                    USERNAME_KEY: '<str>',
                    PASSWORD_KEY: '<str>',
                    ENCRYPTED_ONLY_KEY: <bool>,
                }
        @type config: dict
        """
        # assert params
        leap_assert_type(user, smtp.User)
        leap_assert_type(keymanager, KeyManager)
        assert_config_structure(config)
        # and store them
        self._fromAddress = fromAddress
        self._user = user
        self._km = keymanager
        self._config = config
        # initialize list for message's lines
        self.lines = []

    def lineReceived(self, line):
        """
        Handle another line.

        @param line: The received line.
        @type line: str
        """
        self.lines.append(line)

    def eomReceived(self):
        """
        Handle end of message.

        This method will encrypt and send the message.
        """
        log.msg("Message data complete.")
        self.lines.append('')  # add a trailing newline
        self.parseMessage()
        try:
            self._encrypt_and_sign()
            return self.sendMessage()
        except KeyNotFound:
            return None

    def parseMessage(self):
        """
        Separate message headers from body.
        """
        parser = Parser()
        self._message = parser.parsestr('\r\n'.join(self.lines))

    def connectionLost(self):
        """
        Log an error when the connection is lost.
        """
        log.msg("Connection lost unexpectedly!")
        log.err()
        # unexpected loss of connection; don't save
        self.lines = []

    def sendSuccess(self, r):
        """
        Callback for a successful send.

        @param r: The result from the last previous callback in the chain.
        @type r: anything
        """
        log.msg(r)

    def sendError(self, e):
        """
        Callback for an unsuccessfull send.

        @param e: The result from the last errback.
        @type e: anything
        """
        log.msg(e)
        log.err()

    def sendMessage(self):
        """
        Send the message.

        This method will prepare the message (headers and possibly encrypted
        body) and send it using the ESMTPSenderFactory.

        @return: A deferred with callbacks for error and success of this
            message send.
        @rtype: twisted.internet.defer.Deferred
        """
        msg = self._message.as_string(False)
        d = defer.Deferred()
        factory = smtp.ESMTPSenderFactory(
            self._config[USERNAME_KEY],
            self._config[PASSWORD_KEY],
            self._fromAddress.addrstr,
            self._user.dest.addrstr,
            StringIO(msg),
            d,
            requireAuthentication=False,  # for now do unauth, see issue #2474
        )
        # TODO: Change this to connectSSL when cert auth is in place in the platform
        reactor.connectTCP(
            self._config[HOST_KEY],
            self._config[PORT_KEY],
            factory
        )
        d.addCallback(self.sendSuccess)
        d.addErrback(self.sendError)
        return d

    def _encrypt_and_sign_payload_rec(self, message, pubkey, signkey):
        """
        Recursivelly descend in C{message}'s payload encrypting to C{pubkey}
        and signing with C{signkey}.

        @param message: The message whose payload we want to encrypt.
        @type message: email.message.Message
        @param pubkey: The public key used to encrypt the message.
        @type pubkey: leap.common.keymanager.openpgp.OpenPGPKey
        @param signkey: The private key used to sign the message.
        @type signkey: leap.common.keymanager.openpgp.OpenPGPKey
        """
        if message.is_multipart() is False:
            message.set_payload(
                encrypt_asym(
                    message.get_payload(), pubkey, sign=signkey))
        else:
            for msg in message.get_payload():
                self._encrypt_and_sign_payload_rec(msg, pubkey, signkey)

    def _sign_payload_rec(self, message, signkey):
        """
        Recursivelly descend in C{message}'s payload signing with C{signkey}.

        @param message: The message whose payload we want to encrypt.
        @type message: email.message.Message
        @param pubkey: The public key used to encrypt the message.
        @type pubkey: leap.common.keymanager.openpgp.OpenPGPKey
        @param signkey: The private key used to sign the message.
        @type signkey: leap.common.keymanager.openpgp.OpenPGPKey
        """
        if message.is_multipart() is False:
            message.set_payload(
                sign(
                    message.get_payload(), signkey))
        else:
            for msg in message.get_payload():
                self._sign_payload_rec(msg, signkey)

    def _encrypt_and_sign(self):
        """
        Encrypt the message body.

        Fetch the recipient key and encrypt the content to the
        recipient. If a key is not found, then the behaviour depends on the
        configuration parameter ENCRYPTED_ONLY_KEY. If it is False, the message
        is sent unencrypted and a warning is logged. If it is True, the
        encryption fails with a KeyNotFound exception.

        @raise KeyNotFound: Raised when the recipient key was not found and
            the ENCRYPTED_ONLY_KEY configuration parameter is set to True.
        """
        from_address = validate_address(self._fromAddress.addrstr)
        signkey = self._km.get_key(from_address, OpenPGPKey, private=True)
        log.msg("Will sign the message with %s." % signkey.fingerprint)
        to_address = validate_address(self._user.dest.addrstr)
        try:
            # try to get the recipient pubkey
            pubkey = self._km.get_key(to_address, OpenPGPKey)
            log.msg("Will encrypt the message to %s." % pubkey.fingerprint)
            self._encrypt_and_sign_payload_rec(self._message, pubkey, signkey)
        except KeyNotFound:
            # at this point we _can_ send unencrypted mail, because if the
            # configuration said the opposite the address would have been
            # rejected in SMTPDelivery.validateTo().
            self._sign_payload_rec(self._message, signkey)
            log.msg('Will send unencrypted message to %s.' % to_address)
