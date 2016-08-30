# -*- coding: utf-8 -*-
# server.py
# Copyright (C) 2014 LEAP
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
LEAP IMAP4 Server Implementation.
"""
import StringIO
from copy import copy

from twisted.internet.defer import maybeDeferred
from twisted.mail import imap4
from twisted.python import log

# imports for LITERAL+ patch
from twisted.internet import defer, interfaces
from twisted.mail.imap4 import IllegalClientResponse
from twisted.mail.imap4 import LiteralString, LiteralFile

from leap.common.events import emit_async, catalog


def _getContentType(msg):
    """
    Return a two-tuple of the main and subtype of the given message.
    """
    attrs = None
    mm = msg.getHeaders(False, 'content-type').get('content-type', None)
    if mm:
        mm = ''.join(mm.splitlines())
        mimetype = mm.split(';')
        if mimetype:
            type = mimetype[0].split('/', 1)
            if len(type) == 1:
                major = type[0]
                minor = None
            elif len(type) == 2:
                major, minor = type
            else:
                major = minor = None
            # XXX patched ---------------------------------------------
            attrs = dict(x.strip().split('=', 1) for x in mimetype[1:])
            # XXX patched ---------------------------------------------
        else:
            major = minor = None
    else:
        major = minor = None
    return major, minor, attrs

# Monkey-patch _getContentType to avoid bug that passes lower-case boundary in
# BODYSTRUCTURE response.
imap4._getContentType = _getContentType


class LEAPIMAPServer(imap4.IMAP4Server):
    """
    An IMAP4 Server with a LEAP Storage Backend.
    """

    #############################################################
    #
    # Twisted imap4 patch to workaround bad mime rendering  in TB.
    # See https://leap.se/code/issues/6773
    # and https://bugzilla.mozilla.org/show_bug.cgi?id=149771
    # Still unclear if this is a thunderbird bug.
    # TODO send this patch upstream
    #
    #############################################################

    def spew_body(self, part, id, msg, _w=None, _f=None):
        if _w is None:
            _w = self.transport.write
        for p in part.part:
            if msg.isMultipart():
                msg = msg.getSubPart(p)
            elif p > 0:
                # Non-multipart messages have an implicit first part but no
                # other parts - reject any request for any other part.
                raise TypeError("Requested subpart of non-multipart message")

        if part.header:
            hdrs = msg.getHeaders(part.header.negate, *part.header.fields)
            hdrs = imap4._formatHeaders(hdrs)
            # PATCHED ##########################################
            _w(str(part) + ' ' + imap4._literal(hdrs + "\r\n"))
            # PATCHED ##########################################
        elif part.text:
            _w(str(part) + ' ')
            _f()
            return imap4.FileProducer(
                msg.getBodyFile()
            ).beginProducing(self.transport)
        elif part.mime:
            hdrs = imap4._formatHeaders(msg.getHeaders(True))

            # PATCHED ##########################################
            _w(str(part) + ' ' + imap4._literal(hdrs + "\r\n"))
            # END PATCHED ######################################

        elif part.empty:
            _w(str(part) + ' ')
            _f()
            if part.part:
                # PATCHED #############################################
                # implement partial FETCH
                # TODO implement boundary checks
                # TODO see if there's a more efficient way, without
                # copying the original content into a new buffer.
                fd = msg.getBodyFile()
                begin = getattr(part, "partialBegin", None)
                _len = getattr(part, "partialLength", None)
                if begin is not None and _len is not None:
                    _fd = StringIO.StringIO()
                    fd.seek(part.partialBegin)
                    _fd.write(fd.read(part.partialLength))
                    _fd.seek(0)
                else:
                    _fd = fd
                return imap4.FileProducer(
                    _fd
                    # END PATCHED #########################3
                ).beginProducing(self.transport)
            else:
                mf = imap4.IMessageFile(msg, None)
                if mf is not None:
                    return imap4.FileProducer(
                        mf.open()).beginProducing(self.transport)
                return imap4.MessageProducer(
                    msg, None, self._scheduler).beginProducing(self.transport)

        else:
            _w('BODY ' +
               imap4.collapseNestedLists([imap4.getBodyStructure(msg)]))

    ##################################################################
    #
    # END Twisted imap4 patch to workaround bad mime rendering  in TB.
    # #6773
    #
    ##################################################################

    def lineReceived(self, line):
        """
        Attempt to parse a single line from the server.

        :param line: the line from the server, without the line delimiter.
        :type line: str
        """
        if "login" in line.lower():
            # avoid to log the pass, even though we are using a dummy auth
            # by now.
            msg = line[:7] + " [...]"
        else:
            msg = copy(line)
        log.msg('rcv (%s): %s' % (self.state, msg))
        imap4.IMAP4Server.lineReceived(self, line)

    def close_server_connection(self):
        """
        Send a BYE command so that the MUA at least knows that we're closing
        the connection.
        """
        self.sendLine(
            '* BYE LEAP IMAP Proxy is shutting down; '
            'so long and thanks for all the fish')
        self.transport.loseConnection()
        if self.mbox:
            self.mbox.removeListener(self)
            self.mbox = None
        self.state = 'unauth'

    def do_FETCH(self, tag, messages, query, uid=0):
        """
        Overwritten fetch dispatcher to use the fast fetch_flags
        method
        """
        if not query:
            self.sendPositiveResponse(tag, 'FETCH complete')
            return

        cbFetch = self._IMAP4Server__cbFetch
        ebFetch = self._IMAP4Server__ebFetch

        if len(query) == 1 and str(query[0]) == "flags":
            self._oldTimeout = self.setTimeout(None)
            # no need to call iter, we get a generator
            maybeDeferred(
                self.mbox.fetch_flags, messages, uid=uid
            ).addCallback(
                cbFetch, tag, query, uid
            ).addErrback(ebFetch, tag)

        elif len(query) == 1 and str(query[0]) == "rfc822.header":
            self._oldTimeout = self.setTimeout(None)
            # no need to call iter, we get a generator
            maybeDeferred(
                self.mbox.fetch_headers, messages, uid=uid
            ).addCallback(
                cbFetch, tag, query, uid
            ).addErrback(ebFetch, tag)
        else:
            self._oldTimeout = self.setTimeout(None)
            # no need to call iter, we get a generator
            maybeDeferred(
                self.mbox.fetch, messages, uid=uid
            ).addCallback(
                cbFetch, tag, query, uid
            ).addErrback(
                ebFetch, tag)

    select_FETCH = (do_FETCH, imap4.IMAP4Server.arg_seqset,
                    imap4.IMAP4Server.arg_fetchatt)

    def _cbSelectWork(self, mbox, cmdName, tag):
        """
        Callback for selectWork

        * patched to avoid conformance errors due to incomplete UIDVALIDITY
        line.
        * patched to accept deferreds for messagecount and recent count
        """
        if mbox is None:
            self.sendNegativeResponse(tag, 'No such mailbox')
            return
        if '\\noselect' in [s.lower() for s in mbox.getFlags()]:
            self.sendNegativeResponse(tag, 'Mailbox cannot be selected')
            return

        d1 = defer.maybeDeferred(mbox.getMessageCount)
        d2 = defer.maybeDeferred(mbox.getRecentCount)
        return defer.gatherResults([d1, d2]).addCallback(
            self.__cbSelectWork, mbox, cmdName, tag)

    def __cbSelectWork(self, ((msg_count, recent_count)), mbox, cmdName, tag):
        flags = mbox.getFlags()
        self.sendUntaggedResponse('FLAGS (%s)' % ' '.join(flags))

        # Patched -------------------------------------------------------
        # accept deferreds for the count
        self.sendUntaggedResponse(str(msg_count) + ' EXISTS')
        self.sendUntaggedResponse(str(recent_count) + ' RECENT')
        # ----------------------------------------------------------------

        # Patched -------------------------------------------------------
        # imaptest was complaining about the incomplete line, we're adding
        # "UIDs valid" here.
        self.sendPositiveResponse(
            None, '[UIDVALIDITY %d] UIDs valid' % mbox.getUIDValidity())
        # ----------------------------------------------------------------

        s = mbox.isWriteable() and 'READ-WRITE' or 'READ-ONLY'
        mbox.addListener(self)
        self.sendPositiveResponse(tag, '[%s] %s successful' % (s, cmdName))
        self.state = 'select'
        self.mbox = mbox

    def checkpoint(self):
        """
        Called when the client issues a CHECK command.

        This should perform any checkpoint operations required by the server.
        It may be a long running operation, but may not block.  If it returns
        a deferred, the client will only be informed of success (or failure)
        when the deferred's callback (or errback) is invoked.
        """
        # TODO implement a collection of ongoing deferreds?
        return None

    #############################################################
    #
    # Twisted imap4 patch to support LITERAL+ extension
    # TODO send this patch upstream asap!
    #
    #############################################################

    def capabilities(self):
        cap = {'AUTH': self.challengers.keys()}
        if self.ctx and self.canStartTLS:
            t = self.transport
            ti = interfaces.ISSLTransport
            if not self.startedTLS and ti(t, None) is None:
                cap['LOGINDISABLED'] = None
                cap['STARTTLS'] = None
        cap['NAMESPACE'] = None
        cap['IDLE'] = None
        # patched ############
        cap['LITERAL+'] = None
        ######################
        return cap

    def _stringLiteral(self, size, literal_plus=False):
        if size > self._literalStringLimit:
            raise IllegalClientResponse(
                "Literal too long! I accept at most %d octets" %
                (self._literalStringLimit,))
        d = defer.Deferred()
        self.parseState = 'pending'
        self._pendingLiteral = LiteralString(size, d)
        # Patched ###########################################################
        if not literal_plus:
            self.sendContinuationRequest('Ready for %d octets of text' % size)
        #####################################################################
        self.setRawMode()
        return d

    def _fileLiteral(self, size, literal_plus=False):
        d = defer.Deferred()
        self.parseState = 'pending'
        self._pendingLiteral = LiteralFile(size, d)
        if not literal_plus:
            self.sendContinuationRequest('Ready for %d octets of data' % size)
        self.setRawMode()
        return d

    def arg_astring(self, line):
        """
        Parse an astring from the line, return (arg, rest), possibly
        via a deferred (to handle literals)
        """
        line = line.strip()
        if not line:
            raise IllegalClientResponse("Missing argument")
        d = None
        arg, rest = None, None
        if line[0] == '"':
            try:
                spam, arg, rest = line.split('"', 2)
                rest = rest[1:]  # Strip space
            except ValueError:
                raise IllegalClientResponse("Unmatched quotes")
        elif line[0] == '{':
            # literal
            if line[-1] != '}':
                raise IllegalClientResponse("Malformed literal")

            # Patched ################
            if line[-2] == "+":
                literalPlus = True
                size_end = -2
            else:
                literalPlus = False
                size_end = -1

            try:
                size = int(line[1:size_end])
            except ValueError:
                raise IllegalClientResponse(
                    "Bad literal size: " + line[1:size_end])
            d = self._stringLiteral(size, literalPlus)
            ##########################
        else:
            arg = line.split(' ', 1)
            if len(arg) == 1:
                arg.append('')
            arg, rest = arg
        return d or (arg, rest)

    def arg_literal(self, line):
        """
        Parse a literal from the line
        """
        if not line:
            raise IllegalClientResponse("Missing argument")

        if line[0] != '{':
            raise IllegalClientResponse("Missing literal")

        if line[-1] != '}':
            raise IllegalClientResponse("Malformed literal")

        # Patched ##################
        if line[-2] == "+":
            literalPlus = True
            size_end = -2
        else:
            literalPlus = False
            size_end = -1

        try:
            size = int(line[1:size_end])
        except ValueError:
            raise IllegalClientResponse(
                "Bad literal size: " + line[1:size_end])

        return self._fileLiteral(size, literalPlus)
        #############################

    # --------------------------------- isSubscribed patch
    # TODO -- send patch upstream.
    # There is a bug in twisted implementation:
    # in cbListWork, it's assumed that account.isSubscribed IS a callable,
    # although in the interface documentation it's stated that it can be
    # a deferred.

    def _listWork(self, tag, ref, mbox, sub, cmdName):
        mbox = self._parseMbox(mbox)
        mailboxes = maybeDeferred(self.account.listMailboxes, ref, mbox)
        mailboxes.addCallback(self._cbSubscribed)
        mailboxes.addCallback(
            self._cbListWork, tag, sub, cmdName,
        ).addErrback(self._ebListWork, tag)

    def _cbSubscribed(self, mailboxes):
        subscribed = [
            maybeDeferred(self.account.isSubscribed, name)
            for (name, box) in mailboxes]

        def get_mailboxes_and_subs(result):
            subscribed = [i[0] for i, yes in zip(mailboxes, result) if yes]
            return mailboxes, subscribed

        d = defer.gatherResults(subscribed)
        d.addCallback(get_mailboxes_and_subs)
        return d

    def _cbListWork(self, mailboxes_subscribed, tag, sub, cmdName):
        mailboxes, subscribed = mailboxes_subscribed

        for (name, box) in mailboxes:
            if not sub or name in subscribed:
                flags = box.getFlags()
                delim = box.getHierarchicalDelimiter()
                resp = (imap4.DontQuoteMe(cmdName),
                        map(imap4.DontQuoteMe, flags),
                        delim, name.encode('imap4-utf-7'))
                self.sendUntaggedResponse(
                    imap4.collapseNestedLists(resp))
        self.sendPositiveResponse(tag, '%s completed' % (cmdName,))
    # -------------------- end isSubscribed patch -----------

    # TODO subscribe method had also to be changed to accomodate deferred
    def do_SUBSCRIBE(self, tag, name):
        name = self._parseMbox(name)

        def _subscribeCb(_):
            self.sendPositiveResponse(tag, 'Subscribed')

        def _subscribeEb(failure):
            m = failure.value
            log.err()
            if failure.check(imap4.MailboxException):
                self.sendNegativeResponse(tag, str(m))
            else:
                self.sendBadResponse(
                    tag,
                    "Server error encountered while subscribing to mailbox")

        d = self.account.subscribe(name)
        d.addCallbacks(_subscribeCb, _subscribeEb)
        return d

    auth_SUBSCRIBE = (do_SUBSCRIBE, arg_astring)
    select_SUBSCRIBE = auth_SUBSCRIBE

    def do_UNSUBSCRIBE(self, tag, name):
        # unsubscribe method had also to be changed to accomodate
        # deferred
        name = self._parseMbox(name)

        def _unsubscribeCb(_):
            self.sendPositiveResponse(tag, 'Unsubscribed')

        def _unsubscribeEb(failure):
            m = failure.value
            log.err()
            if failure.check(imap4.MailboxException):
                self.sendNegativeResponse(tag, str(m))
            else:
                self.sendBadResponse(
                    tag,
                    "Server error encountered while unsubscribing "
                    "from mailbox")

        d = self.account.unsubscribe(name)
        d.addCallbacks(_unsubscribeCb, _unsubscribeEb)
        return d

    auth_UNSUBSCRIBE = (do_UNSUBSCRIBE, arg_astring)
    select_UNSUBSCRIBE = auth_UNSUBSCRIBE

    def do_RENAME(self, tag, oldname, newname):
        oldname, newname = [self._parseMbox(n) for n in oldname, newname]
        if oldname.lower() == 'inbox' or newname.lower() == 'inbox':
            self.sendNegativeResponse(
                tag,
                'You cannot rename the inbox, or '
                'rename another mailbox to inbox.')
            return

        def _renameCb(_):
            self.sendPositiveResponse(tag, 'Mailbox renamed')

        def _renameEb(failure):
            m = failure.value
            if failure.check(TypeError):
                self.sendBadResponse(tag, 'Invalid command syntax')
            elif failure.check(imap4.MailboxException):
                self.sendNegativeResponse(tag, str(m))
            else:
                log.err()
                self.sendBadResponse(
                    tag,
                    "Server error encountered while "
                    "renaming mailbox")

        d = self.account.rename(oldname, newname)
        d.addCallbacks(_renameCb, _renameEb)
        return d

    auth_RENAME = (do_RENAME, arg_astring, arg_astring)
    select_RENAME = auth_RENAME

    def do_CREATE(self, tag, name):
        name = self._parseMbox(name)

        def _createCb(result):
            if result:
                self.sendPositiveResponse(tag, 'Mailbox created')
            else:
                self.sendNegativeResponse(tag, 'Mailbox not created')

        def _createEb(failure):
            c = failure.value
            if failure.check(imap4.MailboxException):
                self.sendNegativeResponse(tag, str(c))
            else:
                log.err()
                self.sendBadResponse(
                    tag, "Server error encountered while creating mailbox")

        d = self.account.create(name)
        d.addCallbacks(_createCb, _createEb)
        return d

    auth_CREATE = (do_CREATE, arg_astring)
    select_CREATE = auth_CREATE

    def do_DELETE(self, tag, name):
        name = self._parseMbox(name)
        if name.lower() == 'inbox':
            self.sendNegativeResponse(tag, 'You cannot delete the inbox')
            return

        def _deleteCb(result):
            self.sendPositiveResponse(tag, 'Mailbox deleted')

        def _deleteEb(failure):
            m = failure.value
            if failure.check(imap4.MailboxException):
                self.sendNegativeResponse(tag, str(m))
            else:
                print "SERVER: other error"
                log.err()
                self.sendBadResponse(
                    tag,
                    "Server error encountered while deleting mailbox")

        d = self.account.delete(name)
        d.addCallbacks(_deleteCb, _deleteEb)
        return d

    auth_DELETE = (do_DELETE, arg_astring)
    select_DELETE = auth_DELETE

    # -----------------------------------------------------------------------
    # Patched just to allow __cbAppend to receive a deferred from messageCount
    # TODO format and send upstream.
    def do_APPEND(self, tag, mailbox, flags, date, message):
        mailbox = self._parseMbox(mailbox)
        maybeDeferred(self.account.select, mailbox).addCallback(
            self._cbAppendGotMailbox, tag, flags, date, message).addErrback(
            self._ebAppendGotMailbox, tag)

    def __ebAppend(self, failure, tag):
        self.sendBadResponse(tag, 'APPEND failed: ' + str(failure.value))

    def _cbAppendGotMailbox(self, mbox, tag, flags, date, message):
        if not mbox:
            self.sendNegativeResponse(tag, '[TRYCREATE] No such mailbox')
            return

        d = mbox.addMessage(message, flags, date)
        d.addCallback(self.__cbAppend, tag, mbox)
        d.addErrback(self.__ebAppend, tag)

    def _ebAppendGotMailbox(self, failure, tag):
        self.sendBadResponse(
            tag, "Server error encountered while opening mailbox.")
        log.err(failure)

    def __cbAppend(self, result, tag, mbox):

        # XXX patched ---------------------------------
        def send_response(count):
            self.sendUntaggedResponse('%d EXISTS' % count)
            self.sendPositiveResponse(tag, 'APPEND complete')

        d = mbox.getMessageCount()
        d.addCallback(send_response)
        return d
        # XXX patched ---------------------------------
    # -----------------------------------------------------------------------

    auth_APPEND = (do_APPEND, arg_astring, imap4.IMAP4Server.opt_plist,
                   imap4.IMAP4Server.opt_datetime, arg_literal)
    select_APPEND = auth_APPEND

    # Need to override the command table after patching
    # arg_astring and arg_literal, except on the methods that we are already
    # overriding.

    # TODO --------------------------------------------
    # Check if we really need to override these
    # methods, or we can monkeypatch.
    # do_DELETE = imap4.IMAP4Server.do_DELETE
    # do_CREATE = imap4.IMAP4Server.do_CREATE
    # do_RENAME = imap4.IMAP4Server.do_RENAME
    # do_SUBSCRIBE = imap4.IMAP4Server.do_SUBSCRIBE
    # do_UNSUBSCRIBE = imap4.IMAP4Server.do_UNSUBSCRIBE
    # do_APPEND = imap4.IMAP4Server.do_APPEND
    # -------------------------------------------------
    do_LOGIN = imap4.IMAP4Server.do_LOGIN
    do_STATUS = imap4.IMAP4Server.do_STATUS
    do_COPY = imap4.IMAP4Server.do_COPY

    _selectWork = imap4.IMAP4Server._selectWork

    arg_plist = imap4.IMAP4Server.arg_plist
    arg_seqset = imap4.IMAP4Server.arg_seqset
    opt_plist = imap4.IMAP4Server.opt_plist
    opt_datetime = imap4.IMAP4Server.opt_datetime

    unauth_LOGIN = (do_LOGIN, arg_astring, arg_astring)

    auth_SELECT = (_selectWork, arg_astring, 1, 'SELECT')
    select_SELECT = auth_SELECT

    auth_CREATE = (do_CREATE, arg_astring)
    select_CREATE = auth_CREATE

    auth_EXAMINE = (_selectWork, arg_astring, 0, 'EXAMINE')
    select_EXAMINE = auth_EXAMINE

    # TODO -----------------------------------------------
    # re-add if we stop overriding DELETE
    # auth_DELETE = (do_DELETE, arg_astring)
    # select_DELETE = auth_DELETE
    # auth_APPEND = (do_APPEND, arg_astring, opt_plist, opt_datetime,
    #                arg_literal)
    # select_APPEND = auth_APPEND

    # ----------------------------------------------------

    auth_RENAME = (do_RENAME, arg_astring, arg_astring)
    select_RENAME = auth_RENAME

    auth_SUBSCRIBE = (do_SUBSCRIBE, arg_astring)
    select_SUBSCRIBE = auth_SUBSCRIBE

    auth_UNSUBSCRIBE = (do_UNSUBSCRIBE, arg_astring)
    select_UNSUBSCRIBE = auth_UNSUBSCRIBE

    auth_LIST = (_listWork, arg_astring, arg_astring, 0, 'LIST')
    select_LIST = auth_LIST

    auth_LSUB = (_listWork, arg_astring, arg_astring, 1, 'LSUB')
    select_LSUB = auth_LSUB

    auth_STATUS = (do_STATUS, arg_astring, arg_plist)
    select_STATUS = auth_STATUS

    select_COPY = (do_COPY, arg_seqset, arg_astring)

    #############################################################
    # END of Twisted imap4 patch to support LITERAL+ extension
    #############################################################

    def authenticateLogin(self, user, passwd):
        result = imap4.IMAP4Server.authenticateLogin(self, user, passwd)
        emit_async(catalog.IMAP_CLIENT_LOGIN, str(user))
        return result
