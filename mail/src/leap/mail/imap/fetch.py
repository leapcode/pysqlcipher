# -*- coding: utf-8 -*-
# fetch.py
# Copyright (C) 2013 LEAP
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
Incoming mail fetcher.
"""
import logging
import json
import ssl
import time

from twisted.python import log
from twisted.internet import defer
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThread

from leap.common import events as leap_events
from leap.common.check import leap_assert, leap_assert_type
from leap.soledad import Soledad

from leap.common.events.events_pb2 import IMAP_FETCHED_INCOMING
from leap.common.events.events_pb2 import IMAP_MSG_PROCESSING
from leap.common.events.events_pb2 import IMAP_MSG_DECRYPTED
from leap.common.events.events_pb2 import IMAP_MSG_SAVED_LOCALLY
from leap.common.events.events_pb2 import IMAP_MSG_DELETED_INCOMING
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL


logger = logging.getLogger(__name__)


class LeapIncomingMail(object):
    """
    Fetches mail from the incoming queue.
    """

    ENC_SCHEME_KEY = "_enc_scheme"
    ENC_JSON_KEY = "_enc_json"

    RECENT_FLAG = "\\Recent"

    INCOMING_KEY = "incoming"
    CONTENT_KEY = "content"

    def __init__(self, keymanager, soledad, imap_account,
                 check_period):

        """
        Initialize LeapIMAP.

        :param keymanager: a keymanager instance
        :type keymanager: keymanager.KeyManager

        :param soledad: a soledad instance
        :type soledad: Soledad

        :param imap_account: the account to fetch periodically
        :type imap_account: SoledadBackedAccount

        :param check_period: the period to fetch new mail, in seconds.
        :type check_period: int
        """

        leap_assert(keymanager, "need a keymanager to initialize")
        leap_assert_type(soledad, Soledad)
        leap_assert(check_period, "need a period to check incoming mail")
        leap_assert_type(check_period, int)

        self._keymanager = keymanager
        self._soledad = soledad
        self.imapAccount = imap_account
        self._inbox = self.imapAccount.getMailbox('inbox')

        self._pkey = self._keymanager.get_all_keys_in_local_db(
            private=True).pop()
        self._loop = None
        self._check_period = check_period

        self._create_soledad_indexes()

    def _create_soledad_indexes(self):
        """
        Create needed indexes on soledad.
        """
        self._soledad.create_index("just-mail", "incoming")

    def fetch(self):
        """
        Fetch incoming mail, to be called periodically.

        Calls a deferred that will execute the fetch callback
        in a separate thread
        """
        logger.debug('fetching mail...')
        d = deferToThread(self._sync_soledad)
        d.addCallbacks(self._process_doclist, self._sync_soledad_err)
        return d

    def start_loop(self):
        """
        Starts a loop to fetch mail.
        """
        self._loop = LoopingCall(self.fetch)
        self._loop.start(self._check_period)

    def stop(self):
        """
        Stops the loop that fetches mail.
        """
        if self._loop and self._loop.running is True:
            self._loop.stop()

    def _sync_soledad(self):
        log.msg('syncing soledad...')
        logger.debug('in soledad sync')

        try:
            self._soledad.sync()
            fetched_ts = time.mktime(time.gmtime())
            doclist = self._soledad.get_from_index("just-mail", "*")
            num_mails = len(doclist)
            log.msg("there are %s mails" % (num_mails,))
            leap_events.signal(
                IMAP_FETCHED_INCOMING, str(num_mails), str(fetched_ts))
            leap_events.signal(
                IMAP_UNREAD_MAIL, str(self._inbox.getUnseenCount()))
            return doclist
        except ssl.SSLError as exc:
            logger.warning('SSL Error while syncing soledad: %r' % (exc,))
        except Exception as exc:
            logger.warning('Error while syncing soledad: %r' % (exc,))

    def _sync_soledad_err(self, f):
        log.err("error syncing soledad: %s" % (f.value,))
        return f

    def _process_doclist(self, doclist):
        log.msg('processing doclist')
        if not doclist:
            logger.debug("no docs found")
            return
        num_mails = len(doclist)
        for index, doc in enumerate(doclist):
            logger.debug("processing doc %d of %d: %s" % (
                index, num_mails, doc))
            leap_events.signal(
                IMAP_MSG_PROCESSING, str(index), str(num_mails))
            keys = doc.content.keys()
            if self.ENC_SCHEME_KEY in keys and self.ENC_JSON_KEY in keys:

                # XXX should check for _enc_scheme == "pubkey" || "none"
                # that is what incoming mail uses.
                encdata = doc.content[self.ENC_JSON_KEY]
                d = defer.Deferred(self._decrypt_msg(doc, encdata))
                d.addCallbacks(self._process_decrypted, log.msg)
            else:
                logger.debug('This does not look like a proper msg.')

    def _decrypt_msg(self, doc, encdata):
        log.msg('decrypting msg')
        key = self._pkey
        try:
            decrdata = (self._keymanager.decrypt(
                encdata, key,
                # XXX get from public method instead
                passphrase=self._soledad._passphrase))
            ok = True
        except Exception as exc:
            logger.warning("Error while decrypting msg: %r" % (exc,))
            decrdata = ""
            ok = False
        leap_events.signal(IMAP_MSG_DECRYPTED, ok)
        # XXX TODO: defer this properly
        return self._process_decrypted(doc, decrdata)

    def _process_decrypted(self, doc, data):
        """
        Process a successfully decrypted message.

        :param doc: a SoledadDocument instance containing the incoming message
        :type doc: SoledadDocument

        :param data: the json-encoded, decrypted content of the incoming
                     message
        :type data: str

        :param inbox: a open SoledadMailbox instance where this message is
                      to be saved
        :type inbox: SoledadMailbox
        """
        log.msg("processing incoming message!")
        msg = json.loads(data)
        if not isinstance(msg, dict):
            return False
        if not msg.get(self.INCOMING_KEY, False):
            return False
        # ok, this is an incoming message
        rawmsg = msg.get(self.CONTENT_KEY, None)
        if not rawmsg:
            return False
        logger.debug('got incoming message: %s' % (rawmsg,))

        try:
            pgp_beg = "-----BEGIN PGP MESSAGE-----"
            pgp_end = "-----END PGP MESSAGE-----"
            if pgp_beg in rawmsg:
                first = rawmsg.find(pgp_beg)
                last = rawmsg.rfind(pgp_end)
                pgp_message = rawmsg[first:first+last]

                decrdata = (self._keymanager.decrypt(
                    pgp_message, self._pkey,
                    # XXX get from public method instead
                    passphrase=self._soledad._passphrase))
                rawmsg = rawmsg.replace(pgp_message, decrdata)
            # add to inbox and delete from soledad
            self._inbox.addMessage(rawmsg, (self.RECENT_FLAG,))
            leap_events.signal(IMAP_MSG_SAVED_LOCALLY)
            doc_id = doc.doc_id
            self._soledad.delete_doc(doc)
            log.msg("deleted doc %s from incoming" % doc_id)
            leap_events.signal(IMAP_MSG_DELETED_INCOMING)
        except Exception as e:
            logger.error("Problem processing incoming mail: %r" % (e,))
