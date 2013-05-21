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
SMTP relay helper function.
"""

from twisted.internet import reactor


#from leap import soledad
#from leap.common.keymanager import KeyManager
from leap.mail.smtp.smtprelay import SMTPFactory


def setup_smtp_relay(port, keymanager, smtp_host, smtp_port, smtp_username,
                     smtp_password, encrypted_only):
    """
    Setup SMTP relay to run with Twisted.

    This function sets up the SMTP relay configuration and the Twisted
    reactor.

    @param port: The port in which to run the server.
    @type port: int
    @param keymanager: A Key Manager from where to get recipients' public
        keys.
    @type keymanager: leap.common.keymanager.KeyManager
    @param smtp_host: The hostname of the remote SMTP server.
    @type smtp_host: str
    @param smtp_port:  The port of the remote SMTP server.
    @type smtp_port: int
    @param smtp_username: The username used to connect to remote SMTP server.
    @type smtp_username: str
    @param smtp_password: The password used to connect to remote SMTP server.
    @type smtp_password: str
    @param encrypted_only: Whether the SMTP relay should send unencrypted mail
        or not.
    @type encrypted_only: bool
    """
    # The configuration for the SMTP relay is a dict with the following
    # format:
    #
    # {
    #     'host': '<host>',
    #     'port': <int>,
    #     'username': '<username>',
    #     'password': '<password>',
    #     'encrypted_only': <True/False>
    # }
    config = {
        'host': smtp_host,
        'port': smtp_port,
        'username': smtp_username,
        'password': smtp_password,
        'encrypted_only': encrypted_only
    }

    # configure the use of this service with twistd
    factory = SMTPFactory(keymanager, config)
    reactor.listenTCP(port, factory)
