# -*- coding: utf-8 -*-
# service.py
# Copyright (C) 2015 LEAP
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
import shlex
import threading
import time
import traceback
import warnings

from email.parser import Parser
from email.generator import Generator
from email.utils import parseaddr
from StringIO import StringIO
from urlparse import urlparse

from twisted.application.service import Service
from twisted.python import log
from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.internet.task import deferLater
from u1db import errors as u1db_errors

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
from leap.mail.adaptors import soledad_indexes as fields
from leap.mail.decorators import deferred_to_thread
from leap.mail.utils import json_loads, empty, first
from leap.soledad.client import Soledad
from leap.soledad.common.crypto import ENC_SCHEME_KEY, ENC_JSON_KEY
from leap.soledad.common.errors import InvalidAuthTokenError


logger = logging.getLogger(__name__)

MULTIPART_ENCRYPTED = "multipart/encrypted"
MULTIPART_SIGNED = "multipart/signed"
PGP_BEGIN = "-----BEGIN PGP MESSAGE-----"
PGP_END = "-----END PGP MESSAGE-----"

# The period between succesive checks of the incoming mail
# queue (in seconds)
INCOMING_CHECK_PERIOD = 60


class MalformedMessage(Exception):
    """
    Raised when a given message is not well formed.
    """
    pass


class IncomingMail(Service):
    """
    Fetches and process mail from the incoming pool.

    This object implements IService interface, has public methods
    startService and stopService that will actually initiate a
    LoopingCall with check_period recurrency.
    The LoopingCall itself will invoke the fetch method each time
    that the check_period expires.

    This loop will sync the soledad db with the remote server and
    process all the documents found tagged as incoming mail.
    """

    name = "IncomingMail"

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

    def __init__(self, keymanager, soledad, inbox, userid,
                 check_period=INCOMING_CHECK_PERIOD):

        """
        Initialize IncomingMail..

        :param keymanager: a keymanager instance
        :type keymanager: keymanager.KeyManager

        :param soledad: a soledad instance
        :type soledad: Soledad

        :param inbox: the inbox where the new emails will be stored
        :type inbox: IMAPMailbox

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
        self._inbox = inbox
        self._userid = userid

        self._loop = None
        self._check_period = check_period

        # initialize a mail parser only once
        self._parser = Parser()

    #
    # Public API: fetch, start_loop, stop.
    #

    def fetch(self):
        """
        Fetch incoming mail, to be called periodically.

        Calls a deferred that will execute the fetch callback
        in a separate thread
        """
        def mail_compat(failure):
            if failure.check(u1db_errors.InvalidGlobbing):
                # It looks like we are a dealing with an outdated
                # mx. Fallback to the version of the index
                warnings.warn("JUST_MAIL_COMPAT_IDX will be deprecated!",
                              DeprecationWarning)
                return self._soledad.get_from_index(
                    fields.JUST_MAIL_COMPAT_IDX, "*")
            return failure

        def syncSoledadCallback(_):
            d = self._soledad.get_from_index(
                fields.JUST_MAIL_IDX, "*", "0")
            d.addErrback(mail_compat)
            d.addCallback(self._process_doclist)
            return d

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

    def startService(self):
        """
        Starts a loop to fetch mail.
        """
        Service.startService(self)
        if self._loop is None:
            self._loop = LoopingCall(self.fetch)
            self._loop.start(self._check_period)
        else:
            logger.warning("Tried to start an already running fetching loop.")

    def stopService(self):
        """
        Stops the loop that fetches mail.
        """
        if self._loop and self._loop.running is True:
            self._loop.stop()
            self._loop = None
        Service.stopService(self)

    #
    # Private methods.
    #

    # synchronize incoming mail

    def _errback(self, failure):
        logger.exception(failure.value)
        traceback.print_exc()

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

        deferreds = []
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
            elif self._is_msg(keys):
                d = self._decrypt_doc(doc)
                d.addCallback(self._extract_keys)
                d.addCallbacks(self._add_message_locally, self._errback)
                deferreds.append(d)
        return defer.gatherResults(deferreds, consumeErrors=True)

    #
    # operations on individual messages
    #

    #FIXME: @deferred_to_thread
    def _decrypt_doc(self, doc):
        """
        Decrypt the contents of a document.

        :param doc: A document containing an encrypted message.
        :type doc: SoledadDocument

        :return: A Deferred that will be fired with the document and the
                 decrypted message.
        :rtype: SoledadDocument, str
        """
        log.msg('decrypting msg')

        def process_decrypted(res):
            if isinstance(res, tuple):
                decrdata, _ = res
                success = True
            else:
                decrdata = ""
                success = False

            leap_events.signal(IMAP_MSG_DECRYPTED, "1" if success else "0")
            return self._process_decrypted_doc(doc, decrdata)

        d = self._keymanager.decrypt(
            doc.content[ENC_JSON_KEY],
            self._userid, OpenPGPKey)
        d.addErrback(self._errback)
        d.addCallback(process_decrypted)
        d.addCallback(lambda data: (doc, data))
        return d

    def _process_decrypted_doc(self, doc, data):
        """
        Process a document containing a succesfully decrypted message.

        :param doc: the incoming message
        :type doc: SoledadDocument
        :param data: the json-encoded, decrypted content of the incoming
                     message
        :type data: str

        :return: a Deferred that will be fired with an str of the proccessed
                 data.
        :rtype: Deferred
        """
        log.msg('processing decrypted doc')

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
            return ""
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

        :return: a Deferred that will be fired with an str of data, possibly
                 decrypted.
        :rtype: Deferred
        """
        leap_assert_type(data, str)
        log.msg('maybe decrypting doc')

        # parse the original message
        encoding = get_email_charset(data)
        msg = self._parser.parsestr(data)

        fromHeader = msg.get('from', None)
        senderAddress = None
        if (fromHeader is not None
            and (msg.get_content_type() == MULTIPART_ENCRYPTED
                 or msg.get_content_type() == MULTIPART_SIGNED)):
                senderAddress = parseaddr(fromHeader)

        def add_leap_header(ret):
            decrmsg, signkey = ret
            if (senderAddress is None or
                    isinstance(signkey, keymanager_errors.KeyNotFound)):
                decrmsg.add_header(
                    self.LEAP_SIGNATURE_HEADER,
                    self.LEAP_SIGNATURE_COULD_NOT_VERIFY)
            elif isinstance(signkey, keymanager_errors.InvalidSignature):
                decrmsg.add_header(
                    self.LEAP_SIGNATURE_HEADER,
                    self.LEAP_SIGNATURE_INVALID)
            else:
                decrmsg.add_header(
                    self.LEAP_SIGNATURE_HEADER,
                    self.LEAP_SIGNATURE_VALID,
                    pubkey=signkey.key_id)
            return decrmsg.as_string()

        if msg.get_content_type() == MULTIPART_ENCRYPTED:
            d = self._decrypt_multipart_encrypted_msg(
                msg, encoding, senderAddress)
        else:
            d = self._maybe_decrypt_inline_encrypted_msg(
                msg, encoding, senderAddress)
        d.addCallback(add_leap_header)
        return d

    def _decrypt_multipart_encrypted_msg(self, msg, encoding, senderAddress):
        """
        Decrypt a message with content-type 'multipart/encrypted'.

        :param msg: The original encrypted message.
        :type msg: Message
        :param encoding: The encoding of the email message.
        :type encoding: str
        :param senderAddress: The email address of the sender of the message.
        :type senderAddress: str

        :return: A Deferred that will be fired with a tuple containing a
                 decrypted Message and the signing OpenPGPKey if the signature
                 is valid or InvalidSignature or KeyNotFound.
        :rtype: Deferred
        """
        log.msg('decrypting multipart encrypted msg')
        msg = copy.deepcopy(msg)
        self._msg_multipart_sanity_check(msg)

        # parse message and get encrypted content
        pgpencmsg = msg.get_payload()[1]
        encdata = pgpencmsg.get_payload()

        # decrypt or fail gracefully
        def build_msg(res):
            decrdata, signkey = res

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
            return (msg, signkey)

        d = self._keymanager.decrypt(
            encdata, self._userid, OpenPGPKey,
            verify=senderAddress)
        d.addCallbacks(build_msg, self._decryption_error, errbackArgs=(msg,))
        return d

    def _maybe_decrypt_inline_encrypted_msg(self, origmsg, encoding,
                                            senderAddress):
        """
        Possibly decrypt an inline OpenPGP encrypted message.

        :param origmsg: The original, possibly encrypted message.
        :type origmsg: Message
        :param encoding: The encoding of the email message.
        :type encoding: str
        :param senderAddress: The email address of the sender of the message.
        :type senderAddress: str

        :return: A Deferred that will be fired with a tuple containing a
                 decrypted Message and the signing OpenPGPKey if the signature
                 is valid or InvalidSignature or KeyNotFound.
        :rtype: Deferred
        """
        log.msg('maybe decrypting inline encrypted msg')
        # serialize the original message
        buf = StringIO()
        g = Generator(buf)
        g.flatten(origmsg)
        data = buf.getvalue()

        def decrypted_data(res):
            decrdata, signkey = res
            return data.replace(pgp_message, decrdata), signkey

        def encode_and_return(res):
            data, signkey = res
            if isinstance(data, unicode):
                data = data.encode(encoding, 'replace')
            return (self._parser.parsestr(data), signkey)

        # handle exactly one inline PGP message
        if PGP_BEGIN in data:
            begin = data.find(PGP_BEGIN)
            end = data.find(PGP_END)
            pgp_message = data[begin:end + len(PGP_END)]
            d = self._keymanager.decrypt(
                pgp_message, self._userid, OpenPGPKey,
                verify=senderAddress)
            d.addCallbacks(decrypted_data, self._decryption_error,
                           errbackArgs=(data,))
        else:
            d = defer.succeed((data, None))
        d.addCallback(encode_and_return)
        return d

    def _decryption_error(self, failure, msg):
        """
        Check for known decryption errors
        """
        if failure.check(keymanager_errors.DecryptError):
            logger.warning('Failed to decrypt encrypted message (%s). '
                           'Storing message without modifications.'
                           % str(failure.value))
            return (msg, None)
        elif failure.check(keymanager_errors.KeyNotFound):
            logger.error('Failed to find private key for decryption (%s). '
                         'Storing message without modifications.'
                         % str(failure.value))
            return (msg, None)
        else:
            return failure

    def _extract_keys(self, msgtuple):
        """
        Retrieve attached keys to the mesage and parse message headers for an
        *OpenPGP* header as described on the `IETF draft
        <http://tools.ietf.org/html/draft-josefsson-openpgp-mailnews-header-06>`
        only urls with https and the same hostname than the email are supported
        for security reasons.

        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)

        :return: A Deferred that will be fired with msgtuple when key
                 extraction finishes
        :rtype: Deferred
        """
        OpenPGP_HEADER = 'OpenPGP'
        doc, data = msgtuple

        # XXX the parsing of the message is done in mailbox.addMessage, maybe
        #     we should do it in this module so we don't need to parse it again
        #     here
        msg = self._parser.parsestr(data)
        _, fromAddress = parseaddr(msg['from'])

        header = msg.get(OpenPGP_HEADER, None)
        dh = defer.succeed(None)
        if header is not None:
            dh = self._extract_openpgp_header(header, fromAddress)

        da = defer.succeed(None)
        if msg.is_multipart():
            da = self._extract_attached_key(msg.get_payload(), fromAddress)

        d = defer.gatherResults([dh, da])
        d.addCallback(lambda _: msgtuple)
        return d

    def _extract_openpgp_header(self, header, address):
        """
        Import keys from the OpenPGP header

        :param header: OpenPGP header string
        :type header: str
        :param address: email address in the from header
        :type address: str

        :return: A Deferred that will be fired when header extraction is done
        :rtype: Deferred
        """
        d = defer.succeed(None)
        fields = dict([f.strip(' ').split('=') for f in header.split(';')])
        if 'url' in fields:
            url = shlex.split(fields['url'])[0]  # remove quotations
            urlparts = urlparse(url)
            addressHostname = address.split('@')[1]
            if (urlparts.scheme == 'https'
                    and urlparts.hostname == addressHostname):
                def fetch_error(failure):
                    if failure.check(keymanager_errors.KeyNotFound):
                        logger.warning("Url from OpenPGP header %s failed"
                                       % (url,))
                    elif failure.check(keymanager_errors.KeyAttributesDiffer):
                        logger.warning("Key from OpenPGP header url %s didn't "
                                       "match the from address %s"
                                       % (url, address))
                    else:
                        return failure

                d = self._keymanager.fetch_key(address, url, OpenPGPKey)
                d.addCallback(
                    lambda _:
                    logger.info("Imported key from header %s" % (url,)))
                d.addErrback(fetch_error)
            else:
                logger.debug("No valid url on OpenPGP header %s" % (url,))
        else:
            logger.debug("There is no url on the OpenPGP header: %s"
                         % (header,))
        return d

    def _extract_attached_key(self, attachments, address):
        """
        Import keys from the attachments

        :param attachments: email attachment list
        :type attachments: list(email.Message)
        :param address: email address in the from header
        :type address: str

        :return: A Deferred that will be fired when all the keys are stored
        :rtype: Deferred
        """
        MIME_KEY = "application/pgp-keys"

        deferreds = []
        for attachment in attachments:
            if MIME_KEY == attachment.get_content_type():
                logger.debug("Add key from attachment")
                d = self._keymanager.put_raw_key(
                    attachment.get_payload(),
                    OpenPGPKey,
                    address=address)
                deferreds.append(d)
        return defer.gatherResults(deferreds)

    def _add_message_locally(self, msgtuple):
        """
        Adds a message to local inbox and delete it from the incoming db
        in soledad.

        :param msgtuple: a tuple consisting of a SoledadDocument
                         instance containing the incoming message
                         and data, the json-encoded, decrypted content of the
                         incoming message
        :type msgtuple: (SoledadDocument, str)

        :return: A Deferred that will be fired when the messages is stored
        :rtype: Defferred
        """
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

        d = self._inbox.addMessage(data, (self.RECENT_FLAG,))
        d.addCallbacks(msgSavedCallback, self._errback)
        return d

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
