# -*- coding: utf-8 -*-
# bounces.py
# Copyright (C) 2016 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Deliver bounces to the user Inbox.
"""
import time
from email.message import Message
from email.utils import formatdate

from leap.mail.constants import INBOX_NAME
from leap.mail.mail import Account


# TODO implement localization for this template.

BOUNCE_TEMPLATE = """This is your local Bitmask Mail Agent running at localhost.

I'm sorry to have to inform you that your message could not be delivered to one
or more recipients.

The reasons I got for the error are:

{raw_error}

If the problem persists and it's not a network connectivity issue, you might
want to contact your provider ({provider}) with this information (remove any
sensitive data before).

--- Original message (*before* it was encrypted by bitmask) below ----:

{orig}"""


class Bouncer(object):
    """
    Implements a mechanism to deliver bounces to user inbox.
    """
    # TODO this should follow RFC 6522, and compose a correct multipart
    # attaching the report and the original message. Leaving this for a future
    # iteration.

    def __init__(self, inbox_collection):
        self._inbox_collection = inbox_collection

    def bounce_message(self, error_data, to, date=None, orig=''):
        if not date:
            date = formatdate(time.time())

        raw_data = self._format_msg(error_data, to, date, orig)
        d = self._inbox_collection.add_msg(
            raw_data, ('\\Recent',), date=date)
        return d

    def _format_msg(self, error_data, to, date, orig):
        provider = to.split('@')[1]

        msg = Message()
        msg.add_header(
            'From', 'bitmask-bouncer@localhost (Bitmask Local Agent)')
        msg.add_header('To', to)
        msg.add_header('Subject', 'Undelivered Message')
        msg.add_header('Date', date)
        msg.set_payload(BOUNCE_TEMPLATE.format(
            raw_error=error_data,
            provider=provider,
            orig=orig))

        return msg.as_string()


def bouncerFactory(soledad):
    user_id = soledad.uuid
    acc = Account(soledad, user_id)
    d = acc.callWhenReady(lambda _: acc.get_collection_by_mailbox(INBOX_NAME))
    d.addCallback(lambda inbox: Bouncer(inbox))
    return d
