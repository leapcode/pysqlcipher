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
import threading
import time

from email.parser import Parser

from twisted.python import log
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThread
from zope.proxy import sameProxiedObjects

from leap.common import events as leap_events
from leap.common.check import leap_assert, leap_assert_type
from leap.common.events.events_pb2 import IMAP_FETCHED_INCOMING
from leap.common.events.events_pb2 import IMAP_MSG_PROCESSING
from leap.common.events.events_pb2 import IMAP_MSG_DECRYPTED
from leap.common.events.events_pb2 import IMAP_MSG_SAVED_LOCALLY
from leap.common.events.events_pb2 import IMAP_MSG_DELETED_INCOMING
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL
from leap.common.mail import get_email_charset
from leap.keymanager import errors as keymanager_errors
from leap.keymanager.openpgp import OpenPGPKey
from leap.soledad.client import Soledad
from leap.soledad.common.crypto import ENC_SCHEME_KEY, ENC_JSON_KEY


logger = logging.getLogger(__name__)


class MalformedMessage(Exception):
    """
    Raised when a given message is not well formed.
    """
    pass


class LeapIncomingMail(object):
    """
    Fetches mail from the incoming queue.
    """

    RECENT_FLAG = "\\Recent"

    INCOMING_KEY = "incoming"
    CONTENT_KEY = "content"

    fetching_lock = threading.Lock()

    def __init__(self, keymanager, soledad, imap_account,
                 check_period, userid):

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
        leap_assert(userid, "need a userid to initialize")

        self._keymanager = keymanager
        self._soledad = soledad
        self.imapAccount = imap_account
        self._inbox = self.imapAccount.getMailbox('inbox')
        self._userid = userid

        self._loop = None
        self._check_period = check_period

        self._create_soledad_indexes()

    def _create_soledad_indexes(self):
        """
        Create needed indexes on soledad.
        """
        self._soledad.create_index("just-mail", "incoming")

    @property
    def _pkey(self):
        if sameProxiedObjects(self._keymanager, None):
            logger.warning('tried to get key, but null keymanager found')
            return None
        return self._keymanager.get_key(self._userid, OpenPGPKey, private=True)

    #
    # Public API: fetch, start_loop, stop.
    #

    def fetch(self):
        """
        Fetch incoming mail, to be called periodically.

        Calls a deferred that will execute the fetch callback
        in a separate thread
        """
        logger.debug("fetching mail for: %s %s" % (
            self._soledad.uuid, self._userid))
        if not self.fetching_lock.locked():
            d = deferToThread(self._sync_soledad)
            d.addCallbacks(self._signal_fetch_to_ui, self._sync_soledad_error)
            d.addCallbacks(self._process_doclist, self._sync_soledad_error)
            return d
        else:
            logger.debug("Already fetching mail.")

    def start_loop(self):
        """
        Starts a loop to fetch mail.
        """
        if self._loop is None:
            self._loop = LoopingCall(self.fetch)
            self._loop.start(self._check_period)
        else:
            logger.warning("Tried to start an already running fetching loop.")

    def stop(self):
        """
        Stops the loop that fetches mail.
        """
        if self._loop and self._loop.running is True:
            self._loop.stop()
            self._loop = None

    #
    # Private methods.
    #

    # synchronize incoming mail

    def _sync_soledad(self):
        """
        Synchronizes with remote soledad.

        :returns: a list of LeapDocuments, or None.
        :rtype: iterable or None
        """
        with self.fetching_lock:
            log.msg('syncing soledad...')
            self._soledad.sync()
            doclist = self._soledad.get_from_index("just-mail", "*")
        return doclist

    def _signal_unread_to_ui(self):
        """
        Sends unread event to ui.
        """
        leap_events.signal(
            IMAP_UNREAD_MAIL, str(self._inbox.getUnseenCount()))

    def _signal_fetch_to_ui(self, doclist):
        """
        Sends leap events to ui.

        :param doclist: iterable with msg documents.
        :type doclist: iterable.
        :returns: doclist
        :rtype: iterable
        """
        fetched_ts = time.mktime(time.gmtime())
        num_mails = len(doclist)
        log.msg("there are %s mails" % (num_mails,))
        leap_events.signal(
            IMAP_FETCHED_INCOMING, str(num_mails), str(fetched_ts))
        self._signal_unread_to_ui()
        return doclist

    def _sync_soledad_error(self, failure):
        """
        Errback for sync errors.
        """
        # XXX should signal unrecoverable maybe.
        err = failure.value
        logger.error("error syncing soledad: %s" % (err,))
        if failure.check(ssl.SSLError):
            logger.warning('SSL Error while '
                           'syncing soledad: %r' % (err,))
        elif failure.check(Exception):
            logger.warning('Unknown error while '
                           'syncing soledad: %r' % (err,))

    def _log_err(self, failure):
        """
        Generic errback
        """
        err = failure.value
        logger.exception("error!: %r" % (err,))

    def _decryption_error(self, failure):
        """
        Errback for decryption errors.
        """
        # XXX should signal unrecoverable maybe.
        err = failure.value
        logger.error("error decrypting msg: %s" % (err,))

    def _saving_error(self, failure):
        """
        Errback for local save errors.
        """
        # XXX should signal unrecoverable maybe.
        err = failure.value
        logger.error("error saving msg locally: %s" % (err,))

    def _process_doclist(self, doclist):
        """
        Iterates through the doclist, checks if each doc
        looks like a message, and yields a deferred that will decrypt and
        process the message.

        :param doclist: iterable with msg documents.
        :type doclist: iterable.
        :returns: a list of deferreds for individual messages.
        """
        log.msg('processing doclist')
        if not doclist:
            logger.debug("no docs found")
            return
        num_mails = len(doclist)

        docs_cb = []
        for index, doc in enumerate(doclist):
            logger.debug("processing doc %d of %d" % (index, num_mails))
            leap_events.signal(
                IMAP_MSG_PROCESSING, str(index), str(num_mails))
            keys = doc.content.keys()
            if self._is_msg(keys):
                # Ok, this looks like a legit msg.
                # Let's process it!
                encdata = doc.content[ENC_JSON_KEY]

                # Deferred chain for individual messages
                d = deferToThread(self._decrypt_msg, doc, encdata)
                d.addCallback(self._process_decrypted)
                d.addErrback(self._log_err)
                d.addCallback(self._add_message_locally)
                d.addErrback(self._log_err)
                # XXX check this, add_locally should not get called if we
                # get an error in process
                #d.addCallbacks(self._process_decrypted, self._decryption_error)
                #d.addCallbacks(self._add_message_locally, self._saving_error)
                docs_cb.append(d)
            else:
                # Ooops, this does not.
                logger.debug('This does not look like a proper msg.')
        return docs_cb

    #
    # operations on individual messages
    #

    def _is_msg(self, keys):
        """
        Checks if the keys of a dictionary match the signature
        of the document type we use for messages.

        :param keys: iterable containing the strings to match.
        :type keys: iterable of strings.
        :rtype: bool
        """
        return ENC_SCHEME_KEY in keys and ENC_JSON_KEY in keys

    def _decrypt_msg(self, doc, encdata):
        log.msg('decrypting msg')
        key = self._pkey
        try:
            decrdata = (self._keymanager.decrypt(
                encdata, key,
                passphrase=self._soledad.passphrase))
            ok = True
        except Exception as exc:
            # XXX move this to errback !!!
            logger.warning("Error while decrypting msg: %r" % (exc,))
            decrdata = ""
            ok = False
        leap_events.signal(IMAP_MSG_DECRYPTED, "1" if ok else "0")
        return doc, decrdata

    def _process_decrypted(self, msgtuple):
        """
        Process a successfully decrypted message.

        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)
        :returns: a SoledadDocument and the processed data.
        :rtype: (doc, data)
        """
        doc, data = msgtuple
        msg = json.loads(data)
        if not isinstance(msg, dict):
            return False
        if not msg.get(self.INCOMING_KEY, False):
            return False

        # ok, this is an incoming message
        rawmsg = msg.get(self.CONTENT_KEY, None)
        if not rawmsg:
            return False
        try:
            data = self._maybe_decrypt_gpg_msg(rawmsg)
            return doc, data
        except keymanager_errors.EncryptionDecryptionFailed as exc:
            logger.error(exc)
            raise

    def _maybe_decrypt_gpg_msg(self, data):
        """
        Tries to decrypt a gpg message if data looks like one.

        :param data: the text to be decrypted.
        :type data: unicode
        :return: data, possibly descrypted.
        :rtype: str
        """
        # TODO split this method
        leap_assert_type(data, unicode)

        parser = Parser()
        encoding = get_email_charset(data)
        data = data.encode(encoding)
        origmsg = parser.parsestr(data)

        # handle multipart/encrypted messages
        if origmsg.get_content_type() == 'multipart/encrypted':
            # sanity check
            payload = origmsg.get_payload()
            if len(payload) != 2:
                raise MalformedMessage(
                    'Multipart/encrypted messages should have exactly 2 body '
                    'parts (instead of %d).' % len(payload))
            if payload[0].get_content_type() != 'application/pgp-encrypted':
                raise MalformedMessage(
                    "Multipart/encrypted messages' first body part should "
                    "have content type equal to 'application/pgp-encrypted' "
                    "(instead of %s)." % payload[0].get_content_type())
            if payload[1].get_content_type() != 'application/octet-stream':
                raise MalformedMessage(
                    "Multipart/encrypted messages' second body part should "
                    "have content type equal to 'octet-stream' (instead of "
                    "%s)." % payload[1].get_content_type())

            # parse message and get encrypted content
            pgpencmsg = origmsg.get_payload()[1]
            encdata = pgpencmsg.get_payload()

            # decrypt and parse decrypted message
            decrdata = self._keymanager.decrypt(
                encdata, self._pkey,
                passphrase=self._soledad.passphrase)
            try:
                decrdata = decrdata.encode(encoding)
            except (UnicodeEncodeError, UnicodeDecodeError) as e:
                logger.error("Unicode error {0}".format(e))
                decrdata = decrdata.encode(encoding, 'replace')

            decrmsg = parser.parsestr(decrdata)
            # remove original message's multipart/encrypted content-type
            del(origmsg['content-type'])
            # replace headers back in original message
            for hkey, hval in decrmsg.items():
                try:
                    # this will raise KeyError if header is not present
                    origmsg.replace_header(hkey, hval)
                except KeyError:
                    origmsg[hkey] = hval

            # replace payload by unencrypted payload
            origmsg.set_payload(decrmsg.get_payload())
            return origmsg.as_string(unixfrom=False)
        else:
            PGP_BEGIN = "-----BEGIN PGP MESSAGE-----"
            PGP_END = "-----END PGP MESSAGE-----"
            # handle inline PGP messages
            if PGP_BEGIN in data:
                begin = data.find(PGP_BEGIN)
                end = data.rfind(PGP_END)
                pgp_message = data[begin:begin+end]
                decrdata = (self._keymanager.decrypt(
                    pgp_message, self._pkey,
                    passphrase=self._soledad.passphrase))
                # replace encrypted by decrypted content
                data = data.replace(pgp_message, decrdata)
        # if message is not encrypted, return raw data

        if isinstance(data, unicode):
            data = data.encode(encoding, 'replace')

        return data

    def _add_message_locally(self, msgtuple):
        """
        Adds a message to local inbox and delete it from the incoming db
        in soledad.

        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)
        """
        doc, data = msgtuple
        self._inbox.addMessage(data, (self.RECENT_FLAG,))
        leap_events.signal(IMAP_MSG_SAVED_LOCALLY)
        doc_id = doc.doc_id
        self._soledad.delete_doc(doc)
        log.msg("deleted doc %s from incoming" % doc_id)
        leap_events.signal(IMAP_MSG_DELETED_INCOMING)
        self._signal_unread_to_ui()
