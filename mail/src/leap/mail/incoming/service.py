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
import time
import warnings

from email.parser import Parser
from email.utils import parseaddr
from email.utils import formatdate
from StringIO import StringIO
from urlparse import urlparse

from twisted.application.service import Service
from twisted.python import log
from twisted.python.failure import Failure
from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.internet.task import deferLater

from leap.common.events import emit_async, catalog
from leap.common.check import leap_assert, leap_assert_type
from leap.common.mail import get_email_charset
from leap.keymanager import errors as keymanager_errors
from leap.keymanager.openpgp import OpenPGPKey
from leap.mail.adaptors import soledad_indexes as fields
from leap.mail.generator import Generator
from leap.mail.utils import json_loads, empty
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
    # TODO implements IService?

    name = "IncomingMail"

    RECENT_FLAG = "\\Recent"
    CONTENT_KEY = "content"

    LEAP_SIGNATURE_HEADER = 'X-Leap-Signature'
    LEAP_ENCRYPTION_HEADER = 'X-Leap-Encryption'
    """
    Header added to messages when they are decrypted by the fetcher,
    which states the validity of an eventual signature that might be included
    in the encrypted blob.
    """
    LEAP_SIGNATURE_VALID = 'valid'
    LEAP_SIGNATURE_INVALID = 'invalid'
    LEAP_SIGNATURE_COULD_NOT_VERIFY = 'could not verify'

    LEAP_ENCRYPTION_DECRYPTED = 'decrypted'

    def __init__(self, keymanager, soledad, inbox, userid,
                 check_period=INCOMING_CHECK_PERIOD):

        """
        Initialize IncomingMail..

        :param keymanager: a keymanager instance
        :type keymanager: keymanager.KeyManager

        :param soledad: a soledad instance
        :type soledad: Soledad

        :param inbox: the collection for the inbox where the new emails will be
                      stored
        :type inbox: MessageCollection

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
        self._inbox_collection = inbox
        self._userid = userid

        self._listeners = []
        self._loop = None
        self._check_period = check_period

        # initialize a mail parser only once
        self._parser = Parser()

    def add_listener(self, listener):
        """
        Add a listener to inbox insertions.

        This listener function will be called for each message added to the
        inbox with its uid as parameter. This function should not be blocking
        or it will block the incoming queue.

        :param listener: the listener function
        :type listener: callable
        """
        self._listeners.append(listener)

    #
    # Public API: fetch, start_loop, stop.
    #

    def fetch(self):
        """
        Fetch incoming mail, to be called periodically.

        Calls a deferred that will execute the fetch callback
        in a separate thread
        """
        def _sync_errback(failure):
            log.err(failure)

        def syncSoledadCallback(_):
            # XXX this should be moved to adaptors
            d = self._soledad.get_from_index(
                fields.JUST_MAIL_IDX, "1", "0")
            d.addCallback(self._process_doclist)
            d.addErrback(_sync_errback)
            return d

        logger.debug("fetching mail for: %s %s" % (
            self._soledad.uuid, self._userid))
        d = self._sync_soledad()
        d.addCallbacks(syncSoledadCallback, self._errback)
        d.addCallbacks(self._signal_fetch_to_ui, self._errback)
        return d

    def startService(self):
        """
        Starts a loop to fetch mail.

        :returns: A Deferred whose callback will be invoked with
                  the LoopingCall instance when loop.stop is called, or
                  whose errback will be invoked when the function raises an
                  exception or returned a deferred that has its errback
                  invoked.
        """
        Service.startService(self)
        if self._loop is None:
            self._loop = LoopingCall(self.fetch)
            stop_deferred = self._loop.start(self._check_period)
            return stop_deferred
        else:
            logger.warning("Tried to start an already running fetching loop.")
            return defer.fail(Failure('Already running loop.'))

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
        log.err(failure)

    def _sync_soledad(self):
        """
        Synchronize with remote soledad.

        :returns: a list of LeapDocuments, or None.
        :rtype: iterable or None
        """
        def _log_synced(result):
            log.msg('FETCH soledad SYNCED.')
            return result

        def _signal_invalid_auth(failure):
            failure.trap(InvalidAuthTokenError)
            # if the token is invalid, send an event so the GUI can
            # disable mail and show an error message.
            emit_async(catalog.SOLEDAD_INVALID_AUTH_TOKEN, self._userid)

        log.msg('FETCH: syncing soledad...')
        d = self._soledad.sync()
        d.addCallbacks(_log_synced, _signal_invalid_auth)
        return d

    def _signal_fetch_to_ui(self, doclist):
        """
        Send leap events to ui.

        :param doclist: iterable with msg documents.
        :type doclist: iterable.
        :returns: doclist
        :rtype: iterable
        """
        if doclist:
            fetched_ts = time.mktime(time.gmtime())
            num_mails = len(doclist) if doclist is not None else 0
            if num_mails != 0:
                log.msg("there are %s mails" % (num_mails,))
            emit_async(catalog.MAIL_FETCHED_INCOMING, self._userid,
                       str(num_mails), str(fetched_ts))
            return doclist

    def _signal_unread_to_ui(self, *args):
        """
        Sends unread event to ui.
        """
        emit_async(catalog.MAIL_UNREAD_MESSAGES, self._userid,
                   str(self._inbox_collection.count_unseen()))

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
            emit_async(catalog.MAIL_MSG_PROCESSING, self._userid,
                       str(index), str(num_mails))

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
                d.addCallback(self._maybe_extract_keys)
                d.addCallbacks(self._add_message_locally, self._errback)
                deferreds.append(d)
        d = defer.gatherResults(deferreds, consumeErrors=True)
        d.addCallback(lambda _: doclist)
        return d

    #
    # operations on individual messages
    #

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

            emit_async(catalog.MAIL_MSG_DECRYPTED, self._userid,
                       "1" if success else "0")
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
        if rawmsg is None:
            return ""
        return self._maybe_decrypt_msg(rawmsg)

    def _update_incoming_message(self, doc):
        """
        Do a put for a soledad document. This probably has been called only
        in the case that we've needed to update the ERROR_DECRYPTING_KEY
        flag in an incoming message, to get it out of the decrypting queue.

        :param doc: the SoledadDocument to update
        :type doc: SoledadDocument
        """
        log.msg("Updating Incoming MSG: SoledadDoc %s" % (doc.doc_id))
        return self._soledad.put_doc(doc)

    def _delete_incoming_message(self, doc):
        """
        Delete document.

        :param doc: the SoledadDocument to delete
        :type doc: SoledadDocument
        """
        log.msg("Deleting Incoming message: %s" % (doc.doc_id,))
        return self._soledad.delete_doc(doc)

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

        if (fromHeader is not None and
            (msg.get_content_type() == MULTIPART_ENCRYPTED or
             msg.get_content_type() == MULTIPART_SIGNED)):
                senderAddress = parseaddr(fromHeader)[1]

        def add_leap_header(ret):
            decrmsg, signkey = ret
            if (senderAddress is None or signkey is None or
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
                    pubkey=signkey.fingerprint)
            return decrmsg.as_string()

        if msg.get_content_type() == MULTIPART_ENCRYPTED:
            d = self._decrypt_multipart_encrypted_msg(
                msg, encoding, senderAddress)
        elif msg.get_content_type() == MULTIPART_SIGNED:
            d = self._verify_signature_not_encrypted_msg(msg, senderAddress)
        else:
            d = self._maybe_decrypt_inline_encrypted_msg(
                msg, encoding, senderAddress)
        d.addCallback(add_leap_header)
        return d

    def _add_decrypted_header(self, msg):
        msg.add_header(self.LEAP_ENCRYPTION_HEADER,
                       self.LEAP_ENCRYPTION_DECRYPTED)

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
            self._add_decrypted_header(msg)
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

        data = self._serialize_msg(origmsg)

        def decrypted_data(res):
            decrdata, signkey = res
            replaced_data = data.replace(pgp_message, decrdata)
            self._add_decrypted_header(origmsg)
            return replaced_data, signkey

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

    def _verify_signature_not_encrypted_msg(self, origmsg, sender_address):
        """
        Possibly decrypt an inline OpenPGP encrypted message.

        :param origmsg: The original, possibly encrypted message.
        :type origmsg: Message
        :param sender_address: The email address of the sender of the message.
        :type sender_address: str

        :return: A Deferred that will be fired with a tuple containing a
        signed Message and the signing OpenPGPKey if the signature
        is valid or InvalidSignature.
        :rtype: Deferred
        """
        msg = copy.deepcopy(origmsg)
        data = self._serialize_msg(msg.get_payload(0))
        detached_sig = self._extract_signature(msg)
        d = self._keymanager.verify(data, sender_address, OpenPGPKey,
                                    detached_sig)

        d.addCallback(lambda sign_key: (msg, sign_key))
        d.addErrback(lambda _: (msg, keymanager_errors.InvalidSignature()))
        return d

    def _serialize_msg(self, origmsg):
        buf = StringIO()
        g = Generator(buf)
        g.flatten(origmsg)
        return buf.getvalue()

    def _extract_signature(self, msg):
        body = msg.get_payload(0).get_payload()

        if isinstance(body, str):
            body = msg.get_payload(0)

        detached_sig = msg.get_payload(1).get_payload()
        msg.set_payload(body)
        return detached_sig

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

    @defer.inlineCallbacks
    def _maybe_extract_keys(self, msgtuple):
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

        valid_attachment = False
        if msg.is_multipart():
            valid_attachment = yield self._maybe_extract_attached_key(
                msg.get_payload(), fromAddress)

        if not valid_attachment:
            header = msg.get(OpenPGP_HEADER, None)
            if header is not None:
                yield self._maybe_extract_openpgp_header(header, fromAddress)

        defer.returnValue(msgtuple)

    def _maybe_extract_openpgp_header(self, header, address):
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
            if (
                urlparts.scheme == 'https' and
                urlparts.hostname == addressHostname
            ):
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

    def _maybe_extract_attached_key(self, attachments, address):
        """
        Import keys from the attachments

        :param attachments: email attachment list
        :type attachments: list(email.Message)
        :param address: email address in the from header
        :type address: str

        :return: A Deferred that will be fired when all the keys are stored
                 with a boolean: True if there was a valid key attached, or
                 False otherwise.
        :rtype: Deferred
        """
        MIME_KEY = "application/pgp-keys"

        def log_key_added(ignored):
            logger.debug('Added key found in attachment for %s' % address)
            return True

        def failed_put_key(failure):
            logger.info("An error has ocurred adding attached key for %s: %s"
                        % (address, failure.getErrorMessage()))
            return False

        deferreds = []
        for attachment in attachments:
            if MIME_KEY == attachment.get_content_type():
                d = self._keymanager.put_raw_key(
                    attachment.get_payload(),
                    OpenPGPKey,
                    address=address)
                d.addCallbacks(log_key_added, failed_put_key)
                deferreds.append(d)
        d = defer.gatherResults(deferreds)
        d.addCallback(lambda result: any(result))
        return d

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
        doc, raw_data = msgtuple
        insertion_date = formatdate(time.time())
        log.msg('adding message %s to local db' % (doc.doc_id,))

        def msgSavedCallback(result):
            if empty(result):
                return

            for listener in self._listeners:
                listener(result)

            def signal_deleted(doc_id):
                emit_async(catalog.MAIL_MSG_DELETED_INCOMING,
                           self._userid)
                return doc_id

            emit_async(catalog.MAIL_MSG_SAVED_LOCALLY, self._userid)
            d = self._delete_incoming_message(doc)
            d.addCallback(signal_deleted)
            return d

        d = self._inbox_collection.add_msg(
            raw_data, (self.RECENT_FLAG,), date=insertion_date)
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
