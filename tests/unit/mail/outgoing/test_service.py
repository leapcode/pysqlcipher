# -*- coding: utf-8 -*-
# test_service.py
# Copyright (C) 2016 LEAP
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

import unittest

from mock import MagicMock
from twisted.python.failure import Failure

from leap.bitmask.mail.outgoing.service import OutgoingMail


class TestService(unittest.TestCase):

    def setUp(self):
        self.from_address = 'testing@address.com'
        self.keymanager = MagicMock()
        self.cert = u'cert'
        self.key = u'key'
        self.host = 'address.com'
        self.port = 1234

    def test_send_error_bounces_if_bouncer_is_provided(self):
        bouncer = MagicMock()
        outgoing_mail = OutgoingMail(self.from_address, self.keymanager,
                                     self.cert, self.key, self.host, self.port,
                                     bouncer)

        failure = Failure(exc_value=Exception())
        origmsg = 'message'
        outgoing_mail.sendError(failure, origmsg)

        bouncer.bounce_message.assert_called()

    def test_send_error_raises_exception_if_there_is_no_bouncer(self):
        bouncer = None
        outgoing_mail = OutgoingMail(self.from_address, self.keymanager,
                                     self.cert, self.key, self.host, self.port,
                                     bouncer)

        failure = Failure(exc_value=Exception('smtp error'))
        origmsg = 'message'
        with self.assertRaises(Exception):
            outgoing_mail.sendError(failure, origmsg)
