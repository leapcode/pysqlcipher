# -*- coding: utf-8 -*-
# __init__.py
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
SMTP gateway helper function.
"""
import logging

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from leap.mail.outgoing.service import OutgoingMail

logger = logging.getLogger(__name__)

from leap.common.events import proto, signal
from leap.mail.smtp.gateway import SMTPFactory


def setup_smtp_gateway(port, userid, keymanager, smtp_host, smtp_port,
                       smtp_cert, smtp_key, encrypted_only):
    """
    Setup SMTP gateway to run with Twisted.

    This function sets up the SMTP gateway configuration and the Twisted
    reactor.

    :param port: The port in which to run the server.
    :type port: int
    :param userid: The user currently logged in
    :type userid: str
    :param keymanager: A Key Manager from where to get recipients' public
                       keys.
    :type keymanager: leap.common.keymanager.KeyManager
    :param smtp_host: The hostname of the remote SMTP server.
    :type smtp_host: str
    :param smtp_port: The port of the remote SMTP server.
    :type smtp_port: int
    :param smtp_cert: The client certificate for authentication.
    :type smtp_cert: str
    :param smtp_key: The client key for authentication.
    :type smtp_key: str
    :param encrypted_only: Whether the SMTP gateway should send unencrypted
                           mail or not.
    :type encrypted_only: bool

    :returns: tuple of SMTPFactory, twisted.internet.tcp.Port
    """
    # configure the use of this service with twistd
    outgoing_mail = OutgoingMail(
        userid, keymanager, smtp_cert, smtp_key, smtp_host, smtp_port)
    factory = SMTPFactory(userid, keymanager, encrypted_only, outgoing_mail)
    try:
        tport = reactor.listenTCP(port, factory, interface="localhost")
        signal(proto.SMTP_SERVICE_STARTED, str(port))
        return factory, tport
    except CannotListenError:
        logger.error("STMP Service failed to start: "
                     "cannot listen in port %s" % port)
        signal(proto.SMTP_SERVICE_FAILED_TO_START, str(port))
    except Exception as exc:
        logger.error("Unhandled error while launching smtp gateway service")
        logger.exception(exc)
