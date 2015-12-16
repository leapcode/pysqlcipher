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
import os

from twisted.internet import reactor
from twisted.internet.error import CannotListenError

from leap.common.events import emit_async, catalog

from leap.mail.smtp.gateway import SMTPFactory

logger = logging.getLogger(__name__)


SMTP_PORT = 2013


def run_service(soledad_sessions, keymanager_sessions, sendmail_opts,
                port=SMTP_PORT):
    """
    Main entry point to run the service from the client.

    :param soledad_sessions: a dict-like object, containing instances
                             of a Store (soledad instances), indexed by userid.
    :param keymanager_sessions: a dict-like object, containing instances
                                of Keymanager, indexed by userid.
    :param sendmail_opts: a dict-like object of sendmailOptions.

    :returns: the port as returned by the reactor when starts listening, and
              the factory for the protocol.
    :rtype: tuple
    """
    factory = SMTPFactory(soledad_sessions, keymanager_sessions,
                          sendmail_opts)

    try:
        interface = "localhost"
        # don't bind just to localhost if we are running on docker since we
        # won't be able to access smtp from the host
        if os.environ.get("LEAP_DOCKERIZED"):
            interface = ''

        # TODO Use Endpoints instead --------------------------------
        tport = reactor.listenTCP(port, factory, interface=interface)
        emit_async(catalog.SMTP_SERVICE_STARTED, str(port))

        return factory, tport
    except CannotListenError:
        logger.error("STMP Service failed to start: "
                     "cannot listen in port %s" % port)
        emit_async(catalog.SMTP_SERVICE_FAILED_TO_START, str(port))
    except Exception as exc:
        logger.error("Unhandled error while launching smtp gateway service")
        logger.exception(exc)
