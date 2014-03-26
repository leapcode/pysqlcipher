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
import copy
import logging
import threading
import time
import sys
import traceback
import warnings

from email.parser import Parser
from email.generator import Generator
from email.utils import parseaddr
from StringIO import StringIO

from twisted.python import log
from twisted.internet import defer
from twisted.internet.task import LoopingCall
from twisted.internet.task import deferLater
from u1db import errors as u1db_errors
from zope.proxy import sameProxiedObjects

from leap.common import events as leap_events
from leap.common.check import leap_assert, leap_assert_type
from leap.common.events.events_pb2 import IMAP_FETCHED_INCOMING
from leap.common.events.events_pb2 import IMAP_MSG_PROCESSING
from leap.common.events.events_pb2 import IMAP_MSG_DECRYPTED
from leap.common.events.events_pb2 import IMAP_MSG_SAVED_LOCALLY
from leap.common.events.events_pb2 import IMAP_MSG_DELETED_INCOMING
from leap.common.events.events_pb2 import IMAP_UNREAD_MAIL
from leap.common.events.events_pb2 import SOLEDAD_INVALID_AUTH_TOKEN
from leap.common.mail import get_email_charset
from leap.keymanager import errors as keymanager_errors
from leap.keymanager.openpgp import OpenPGPKey
from leap.mail.decorators import deferred_to_thread
from leap.mail.imap.fields import fields
from leap.mail.utils import json_loads, empty, first
from leap.soledad.client import Soledad
from leap.soledad.common.crypto import ENC_SCHEME_KEY, ENC_JSON_KEY
from leap.soledad.common.errors import InvalidAuthTokenError


logger = logging.getLogger(__name__)

MULTIPART_ENCRYPTED = "multipart/encrypted"
MULTIPART_SIGNED = "multipart/signed"
PGP_BEGIN = "-----BEGIN PGP MESSAGE-----"
PGP_END = "-----END PGP MESSAGE-----"


class MalformedMessage(Exception):
    """
    Raised when a given message is not well formed.
    """
    pass


class LeapIncomingMail(object):
    """
    Fetches and process mail from the incoming pool.

    This object has public methods start_loop and stop that will
    actually initiate a LoopingCall with check_period recurrency.
    The LoopingCall itself will invoke the fetch method each time
    that the check_period expires.

    This loop will sync the soledad db with the remote server and
    process all the documents found tagged as incoming mail.
    """

    RECENT_FLAG = "\\Recent"
    CONTENT_KEY = "content"

    LEAP_SIGNATURE_HEADER = 'X-Leap-Signature'
    """
    Header added to messages when they are decrypted by the IMAP fetcher,
    which states the validity of an eventual signature that might be included
    in the encrypted blob.
    """
    LEAP_SIGNATURE_VALID = 'valid'
    LEAP_SIGNATURE_INVALID = 'invalid'
    LEAP_SIGNATURE_COULD_NOT_VERIFY = 'could not verify'

    fetching_lock = threading.Lock()

    def __init__(self, keymanager, soledad, imap_account,
                 check_period, userid):

        """
        Initialize LeapIncomingMail..

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

        # initialize a mail parser only once
        self._parser = Parser()

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
        def syncSoledadCallback(result):
            # FIXME this needs a matching change in mx!!!
            # --> need to add ERROR_DECRYPTING_KEY = False
            # as default.
            try:
                doclist = self._soledad.get_from_index(
                    fields.JUST_MAIL_IDX, "*", "0")
            except u1db_errors.InvalidGlobbing:
                # It looks like we are a dealing with an outdated
                # mx. Fallback to the version of the index
                warnings.warn("JUST_MAIL_COMPAT_IDX will be deprecated!",
                              DeprecationWarning)
                doclist = self._soledad.get_from_index(
                    fields.JUST_MAIL_COMPAT_IDX, "*")
            self._process_doclist(doclist)

        logger.debug("fetching mail for: %s %s" % (
            self._soledad.uuid, self._userid))
        if not self.fetching_lock.locked():
            d1 = self._sync_soledad()
            d = defer.gatherResults([d1], consumeErrors=True)
            d.addCallbacks(syncSoledadCallback, self._errback)
            d.addCallbacks(self._signal_fetch_to_ui, self._errback)
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
        # XXX change the name to stop_loop, for consistency.
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

    def _errback(self, failure):
        logger.exception(failure.value)
        traceback.print_tb(*sys.exc_info())

    @deferred_to_thread
    def _sync_soledad(self):
        """
        Synchronize with remote soledad.

        :returns: a list of LeapDocuments, or None.
        :rtype: iterable or None
        """
        with self.fetching_lock:
            try:
                log.msg('FETCH: syncing soledad...')
                self._soledad.sync()
                log.msg('FETCH soledad SYNCED.')
            except InvalidAuthTokenError:
                # if the token is invalid, send an event so the GUI can
                # disable mail and show an error message.
                leap_events.signal(SOLEDAD_INVALID_AUTH_TOKEN)

    def _signal_fetch_to_ui(self, doclist):
        """
        Send leap events to ui.

        :param doclist: iterable with msg documents.
        :type doclist: iterable.
        :returns: doclist
        :rtype: iterable
        """
        doclist = first(doclist)  # gatherResults pass us a list
        if doclist:
            fetched_ts = time.mktime(time.gmtime())
            num_mails = len(doclist) if doclist is not None else 0
            if num_mails != 0:
                log.msg("there are %s mails" % (num_mails,))
            leap_events.signal(
                IMAP_FETCHED_INCOMING, str(num_mails), str(fetched_ts))
            return doclist

    def _signal_unread_to_ui(self, *args):
        """
        Sends unread event to ui.
        """
        leap_events.signal(
            IMAP_UNREAD_MAIL, str(self._inbox.getUnseenCount()))

    # process incoming mail.

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

        for index, doc in enumerate(doclist):
            logger.debug("processing doc %d of %d" % (index + 1, num_mails))
            leap_events.signal(
                IMAP_MSG_PROCESSING, str(index), str(num_mails))

            keys = doc.content.keys()

            # TODO Compatibility check with the index in pre-0.6 mx
            # that does not write the ERROR_DECRYPTING_KEY
            # This should be removed in 0.7

            has_errors = doc.content.get(fields.ERROR_DECRYPTING_KEY, None)
            if has_errors is None:
                warnings.warn("JUST_MAIL_COMPAT_IDX will be deprecated!",
                              DeprecationWarning)
            if has_errors:
                logger.debug("skipping msg with decrypting errors...")

            if self._is_msg(keys) and not has_errors:
                # Evaluating to bool of has_errors is intentional here.
                # We don't mind at this point if it's None or False.

                # Ok, this looks like a legit msg, and with no errors.
                # Let's process it!

                d1 = self._decrypt_doc(doc)
                d = defer.gatherResults([d1], consumeErrors=True)
                d.addCallbacks(self._add_message_locally, self._errback)

    #
    # operations on individual messages
    #

    @deferred_to_thread
    def _decrypt_doc(self, doc):
        """
        Decrypt the contents of a document.

        :param doc: A document containing an encrypted message.
        :type doc: SoledadDocument

        :return: A tuple containing the document and the decrypted message.
        :rtype: (SoledadDocument, str)
        """
        log.msg('decrypting msg')
        success = False

        try:
            decrdata = self._keymanager.decrypt(
                doc.content[ENC_JSON_KEY],
                self._pkey)
            success = True
        except Exception as exc:
            # XXX move this to errback !!!
            logger.error("Error while decrypting msg: %r" % (exc,))
            decrdata = ""
        leap_events.signal(IMAP_MSG_DECRYPTED, "1" if success else "0")

        data = self._process_decrypted_doc((doc, decrdata))
        return (doc, data)

    def _process_decrypted_doc(self, msgtuple):
        """
        Process a document containing a succesfully decrypted message.

        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)
        :return: a SoledadDocument and the processed data.
        :rtype: (doc, data)
        """
        log.msg('processing decrypted doc')
        doc, data = msgtuple

        from twisted.internet import reactor

        # XXX turn this into an errBack for each one of
        # the deferreds that would process an individual document
        try:
            msg = json_loads(data)
        except UnicodeError as exc:
            logger.error("Error while decrypting %s" % (doc.doc_id,))
            logger.exception(exc)

            # we flag the message as "with decrypting errors",
            # to avoid further decryption attempts during sync
            # cycles until we're prepared to deal with that.
            # What is the same, when Ivan deals with it...
            # A new decrypting attempt event could be triggered by a
            # future a library upgrade, or a cli flag to the client,
            # we just `defer` that for now... :)
            doc.content[fields.ERROR_DECRYPTING_KEY] = True
            deferLater(reactor, 0, self._update_incoming_message, doc)

            # FIXME this is just a dirty hack to delay the proper
            # deferred organization here...
            # and remember, boys, do not do this at home.
            return []

        if not isinstance(msg, dict):
            defer.returnValue(False)
        if not msg.get(fields.INCOMING_KEY, False):
            defer.returnValue(False)

        # ok, this is an incoming message
        rawmsg = msg.get(self.CONTENT_KEY, None)
        if not rawmsg:
            return False
        return self._maybe_decrypt_msg(rawmsg)

    @deferred_to_thread
    def _update_incoming_message(self, doc):
        """
        Do a put for a soledad document. This probably has been called only
        in the case that we've needed to update the ERROR_DECRYPTING_KEY
        flag in an incoming message, to get it out of the decrypting queue.

        :param doc: the SoledadDocument to update
        :type doc: SoledadDocument
        """
        log.msg("Updating SoledadDoc %s" % (doc.doc_id))
        self._soledad.put_doc(doc)

    @deferred_to_thread
    def _delete_incoming_message(self, doc):
        """
        Delete document.

        :param doc: the SoledadDocument to delete
        :type doc: SoledadDocument
        """
        log.msg("Deleting Incoming message: %s" % (doc.doc_id,))
        self._soledad.delete_doc(doc)

    def _maybe_decrypt_msg(self, data):
        """
        Tries to decrypt a gpg message if data looks like one.

        :param data: the text to be decrypted.
        :type data: str
        :return: data, possibly descrypted.
        :rtype: str
        """
        leap_assert_type(data, str)
        log.msg('maybe decrypting doc')

        # parse the original message
        encoding = get_email_charset(data)
        msg = self._parser.parsestr(data)

        # try to obtain sender public key
        senderPubkey = None
        fromHeader = msg.get('from', None)
        if (fromHeader is not None
            and (msg.get_content_type() == MULTIPART_ENCRYPTED
                 or msg.get_content_type() == MULTIPART_SIGNED)):
            _, senderAddress = parseaddr(fromHeader)
            try:
                senderPubkey = self._keymanager.get_key_from_cache(
                    senderAddress, OpenPGPKey)
            except keymanager_errors.KeyNotFound:
                pass

        valid_sig = False  # we will add a header saying if sig is valid
        decrypt_multi = self._decrypt_multipart_encrypted_msg
        decrypt_inline = self._maybe_decrypt_inline_encrypted_msg

        if msg.get_content_type() == MULTIPART_ENCRYPTED:
            decrmsg, valid_sig = decrypt_multi(
                msg, encoding, senderPubkey)
        else:
            decrmsg, valid_sig = decrypt_inline(
                msg, encoding, senderPubkey)

        # add x-leap-signature header
        if senderPubkey is None:
            decrmsg.add_header(
                self.LEAP_SIGNATURE_HEADER,
                self.LEAP_SIGNATURE_COULD_NOT_VERIFY)
        else:
            decrmsg.add_header(
                self.LEAP_SIGNATURE_HEADER,
                self.LEAP_SIGNATURE_VALID if valid_sig else
                self.LEAP_SIGNATURE_INVALID,
                pubkey=senderPubkey.key_id)

        return decrmsg.as_string()

    def _decrypt_multipart_encrypted_msg(self, msg, encoding, senderPubkey):
        """
        Decrypt a message with content-type 'multipart/encrypted'.

        :param msg: The original encrypted message.
        :type msg: Message
        :param encoding: The encoding of the email message.
        :type encoding: str
        :param senderPubkey: The key of the sender of the message.
        :type senderPubkey: OpenPGPKey

        :return: A unitary tuple containing a decrypted message.
        :rtype: (Message)
        """
        log.msg('decrypting multipart encrypted msg')
        msg = copy.deepcopy(msg)
        self._msg_multipart_sanity_check(msg)

        # parse message and get encrypted content
        pgpencmsg = msg.get_payload()[1]
        encdata = pgpencmsg.get_payload()

        # decrypt or fail gracefully
        try:
            decrdata, valid_sig = self._decrypt_and_verify_data(
                encdata, senderPubkey)
        except keymanager_errors.DecryptError as e:
            logger.warning('Failed to decrypt encrypted message (%s). '
                           'Storing message without modifications.' % str(e))
            # Bailing out!
            return (msg, False)

        decrmsg = self._parser.parsestr(decrdata)
        # remove original message's multipart/encrypted content-type
        del(msg['content-type'])

        # replace headers back in original message
        for hkey, hval in decrmsg.items():
            try:
                # this will raise KeyError if header is not present
                msg.replace_header(hkey, hval)
            except KeyError:
                msg[hkey] = hval

        # all ok, replace payload by unencrypted payload
        msg.set_payload(decrmsg.get_payload())
        return (msg, valid_sig)

    def _maybe_decrypt_inline_encrypted_msg(self, origmsg, encoding,
                                            senderPubkey):
        """
        Possibly decrypt an inline OpenPGP encrypted message.

        :param origmsg: The original, possibly encrypted message.
        :type origmsg: Message
        :param encoding: The encoding of the email message.
        :type encoding: str
        :param senderPubkey: The key of the sender of the message.
        :type senderPubkey: OpenPGPKey

        :return: A tuple containing a decrypted message and
                 a bool indicating whether the signature is valid.
        :rtype: (Message, bool)
        """
        log.msg('maybe decrypting inline encrypted msg')
        # serialize the original message
        buf = StringIO()
        g = Generator(buf)
        g.flatten(origmsg)
        data = buf.getvalue()
        # handle exactly one inline PGP message
        valid_sig = False
        if PGP_BEGIN in data:
            begin = data.find(PGP_BEGIN)
            end = data.find(PGP_END)
            pgp_message = data[begin:end + len(PGP_END)]
            try:
                decrdata, valid_sig = self._decrypt_and_verify_data(
                    pgp_message, senderPubkey)
                # replace encrypted by decrypted content
                data = data.replace(pgp_message, decrdata)
            except keymanager_errors.DecryptError:
                logger.warning('Failed to decrypt potential inline encrypted '
                               'message. Storing message as is...')

        # if message is not encrypted, return raw data
        if isinstance(data, unicode):
            data = data.encode(encoding, 'replace')
        return (self._parser.parsestr(data), valid_sig)

    def _decrypt_and_verify_data(self, data, senderPubkey):
        """
        Decrypt C{data} using our private key and attempt to verify a
        signature using C{senderPubkey}.

        :param data: The text to be decrypted.
        :type data: unicode
        :param senderPubkey: The public key of the sender of the message.
        :type senderPubkey: OpenPGPKey

        :return: The decrypted data and a boolean stating whether the
                 signature could be verified.
        :rtype: (str, bool)

        :raise DecryptError: Raised if failed to decrypt.
        """
        log.msg('decrypting and verifying data')
        valid_sig = False
        try:
            decrdata = self._keymanager.decrypt(
                data, self._pkey,
                verify=senderPubkey)
            if senderPubkey is not None:
                valid_sig = True
        except keymanager_errors.InvalidSignature:
            decrdata = self._keymanager.decrypt(
                data, self._pkey)
        return (decrdata, valid_sig)

    def _add_message_locally(self, result):
        """
        Adds a message to local inbox and delete it from the incoming db
        in soledad.

        # XXX this comes from a gatherresult...
        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)
        """
        from twisted.internet import reactor
        msgtuple = first(result)

        doc, data = msgtuple
        log.msg('adding message %s to local db' % (doc.doc_id,))

        if isinstance(data, list):
            if empty(data):
                return False
            data = data[0]

        def msgSavedCallback(result):
            if not empty(result):
                leap_events.signal(IMAP_MSG_SAVED_LOCALLY)
                deferLater(reactor, 0, self._delete_incoming_message, doc)
                leap_events.signal(IMAP_MSG_DELETED_INCOMING)

        d = self._inbox.addMessage(data, flags=(self.RECENT_FLAG,),
                                   notify_on_disk=True)
        d.addCallbacks(msgSavedCallback, self._errback)

    #
    # helpers
    #

    def _msg_multipart_sanity_check(self, msg):
        """
        Performs a sanity check against a multipart encrypted msg

        :param msg: The original encrypted message.
        :type msg: Message
        """
        # sanity check
        payload = msg.get_payload()
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

    def _is_msg(self, keys):
        """
        Checks if the keys of a dictionary match the signature
        of the document type we use for messages.

        :param keys: iterable containing the strings to match.
        :type keys: iterable of strings.
        :rtype: bool
        """
        return ENC_SCHEME_KEY in keys and ENC_JSON_KEY in keys
