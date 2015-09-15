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

    * EncryptedMessage - An implementation of twisted.mail.smtp.IMessage that
      knows how to encrypt/sign itself before sending.
"""

from zope.interface import implements
from twisted.mail import smtp
from twisted.internet.protocol import ServerFactory
from twisted.python import log

from email.Header import Header
from leap.common.check import leap_assert_type
from leap.common.events import emit_async, catalog
from leap.keymanager.openpgp import OpenPGPKey
from leap.keymanager.errors import KeyNotFound
from leap.mail.utils import validate_address

from leap.mail.smtp.rfc3156 import (
    RFC3156CompliantGenerator,
)

# replace email generator with a RFC 3156 compliant one.
from email import generator

generator.Generator = RFC3156CompliantGenerator


#
# Helper utilities
#

LOCAL_FQDN = "bitmask.local"


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

    def __init__(self, userid, keymanager, encrypted_only, outgoing_mail):
        """
        Initialize the SMTP factory.

        :param userid: The user currently logged in
        :type userid: unicode
        :param keymanager: A Key Manager from where to get recipients' public
                           keys.
        :param encrypted_only: Whether the SMTP gateway should send unencrypted
                               mail or not.
        :type encrypted_only: bool
        :param outgoing_mail: The outgoing mail to send the message
        :type outgoing_mail: leap.mail.outgoing.service.OutgoingMail
        """

        leap_assert_type(encrypted_only, bool)
        # and store them
        self._userid = userid
        self._km = keymanager
        self._outgoing_mail = outgoing_mail
        self._encrypted_only = encrypted_only

    def buildProtocol(self, addr):
        """
        Return a protocol suitable for the job.

        :param addr: An address, e.g. a TCP (host, port).
        :type addr:  twisted.internet.interfaces.IAddress

        @return: The protocol.
        @rtype: SMTPDelivery
        """
        smtpProtocol = SMTPHeloLocalhost(
            SMTPDelivery(
                self._userid, self._km, self._encrypted_only,
                self._outgoing_mail))
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

    def __init__(self, userid, keymanager, encrypted_only, outgoing_mail):
        """
        Initialize the SMTP delivery object.

        :param userid: The user currently logged in
        :type userid: unicode
        :param keymanager: A Key Manager from where to get recipients' public
                           keys.
        :param encrypted_only: Whether the SMTP gateway should send unencrypted
                               mail or not.
        :type encrypted_only: bool
        :param outgoing_mail: The outgoing mail to send the message
        :type outgoing_mail: leap.mail.outgoing.service.OutgoingMail
        """
        self._userid = userid
        self._outgoing_mail = outgoing_mail
        self._km = keymanager
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
        Validate the address of a recipient of the message, possibly
        rejecting it if the recipient key is not available.

        This method is called once for each recipient, i.e. for each SMTP
        protocol line beginning with "RCPT TO:", which includes all addresses
        in "To", "Cc" and "Bcc" MUA fields.

        The recipient's address is validated against the RFC 2822 definition.
        If self._encrypted_only is True and no key is found for a recipient,
        then that recipient is rejected.

        The method returns an encrypted message object that is able to send
        itself to the user's address.

        :param user: The user whose address we wish to validate.
        :type: twisted.mail.smtp.User

        @return: A callable which takes no arguments and returns an
                 encryptedMessage.
        @rtype: no-argument callable

        @raise SMTPBadRcpt: Raised if messages to the address are not to be
                            accepted.
        """
        # try to find recipient's public key
        address = validate_address(user.dest.addrstr)

        # verify if recipient key is available in keyring
        def found(_):
            log.msg("Accepting mail for %s..." % user.dest.addrstr)
            emit_async(catalog.SMTP_RECIPIENT_ACCEPTED_ENCRYPTED, user.dest.addrstr)

        def not_found(failure):
            failure.trap(KeyNotFound)

            # if key was not found, check config to see if will send anyway
            if self._encrypted_only:
                emit_async(catalog.SMTP_RECIPIENT_REJECTED, user.dest.addrstr)
                raise smtp.SMTPBadRcpt(user.dest.addrstr)
            log.msg("Warning: will send an unencrypted message (because "
                    "encrypted_only' is set to False).")
            emit_async(
                catalog.SMTP_RECIPIENT_ACCEPTED_UNENCRYPTED,
                user.dest.addrstr)

        def encrypt_func(_):
            return lambda: EncryptedMessage(user, self._outgoing_mail)

        d = self._km.get_key(address, OpenPGPKey)
        d.addCallbacks(found, not_found)
        d.addCallback(encrypt_func)
        return d

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

class EncryptedMessage(object):
    """
    Receive plaintext from client, encrypt it and send message to a
    recipient.
    """
    implements(smtp.IMessage)

    def __init__(self, user, outgoing_mail):
        """
        Initialize the encrypted message.

        :param user: The recipient of this message.
        :type user: twisted.mail.smtp.User
        :param outgoing_mail: The outgoing mail to send the message
        :type outgoing_mail: leap.mail.outgoing.service.OutgoingMail
        """
        # assert params
        leap_assert_type(user, smtp.User)

        self._user = user
        self._lines = []
        self._outgoing_mail = outgoing_mail

    def lineReceived(self, line):
        """
        Handle another line.

        :param line: The received line.
        :type line: str
        """
        self._lines.append(line)

    def eomReceived(self):
        """
        Handle end of message.

        This method will encrypt and send the message.

        :returns: a deferred
        """
        log.msg("Message data complete.")
        self._lines.append('')  # add a trailing newline
        raw_mail = '\r\n'.join(self._lines)

        return self._outgoing_mail.send_message(raw_mail, self._user)

    def connectionLost(self):
        """
        Log an error when the connection is lost.
        """
        log.msg("Connection lost unexpectedly!")
        log.err()
        emit_async(catalog.SMTP_CONNECTION_LOST, self._user.dest.addrstr)
        # unexpected loss of connection; don't save

        self._lines = []
