# -*- coding: utf-8 -*-
# rfc3156.py
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
Implements RFC 3156: MIME Security with OpenPGP.
"""

import base64
from StringIO import StringIO

from twisted.logger import Logger

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email import errors
from email.generator import (
    Generator,
    fcre,
    NL,
    _make_boundary,
)

logger = Logger()

#
# A generator that solves http://bugs.python.org/issue14983
#


class RFC3156CompliantGenerator(Generator):
    """
    An email generator that addresses Python's issue #14983 for multipart
    messages.

    This is just a copy of email.generator.Generator which fixes the following
    bug: http://bugs.python.org/issue14983
    """

    def _handle_multipart(self, msg):
        """
        A multipart handling implementation that addresses issue #14983.

        This is just a copy of the parent's method which fixes the following
        bug: http://bugs.python.org/issue14983 (see the line marked with
        "(***)").

        :param msg: The multipart message to be handled.
        :type msg: email.message.Message
        """
        # The trick here is to write out each part separately, merge them all
        # together, and then make sure that the boundary we've chosen isn't
        # present in the payload.
        msgtexts = []
        subparts = msg.get_payload()
        if subparts is None:
            subparts = []
        elif isinstance(subparts, basestring):
            # e.g. a non-strict parse of a message with no starting boundary.
            self._fp.write(subparts)
            return
        elif not isinstance(subparts, list):
            # Scalar payload
            subparts = [subparts]
        for part in subparts:
            s = StringIO()
            g = self.clone(s)
            g.flatten(part, unixfrom=False)
            msgtexts.append(s.getvalue())
        # BAW: What about boundaries that are wrapped in double-quotes?
        boundary = msg.get_boundary()
        if not boundary:
            # Create a boundary that doesn't appear in any of the
            # message texts.
            alltext = NL.join(msgtexts)
            boundary = _make_boundary(alltext)
            msg.set_boundary(boundary)
        # If there's a preamble, write it out, with a trailing CRLF
        if msg.preamble is not None:
            preamble = msg.preamble
            if self._mangle_from_:
                preamble = fcre.sub('>From ', msg.preamble)
            self._fp.write(preamble + '\n')
        # dash-boundary transport-padding CRLF
        self._fp.write('--' + boundary + '\n')
        # body-part
        if msgtexts:
            self._fp.write(msgtexts.pop(0))
        # *encapsulation
        # --> delimiter transport-padding
        # --> CRLF body-part
        for body_part in msgtexts:
            # delimiter transport-padding CRLF
            self._fp.write('\n--' + boundary + '\n')
            # body-part
            self._fp.write(body_part)
        # close-delimiter transport-padding
        self._fp.write('\n--' + boundary + '--' + '\n')  # (***) Solve #14983
        if msg.epilogue is not None:
            self._fp.write('\n')
            epilogue = msg.epilogue
            if self._mangle_from_:
                epilogue = fcre.sub('>From ', msg.epilogue)
            self._fp.write(epilogue)


#
# Base64 encoding: these are almost the same as python's email.encoder
# solution, but a bit modified.
#

def _bencode(s):
    """
    Encode C{s} in base64.

    :param s: The string to be encoded.
    :type s: str
    """
    # We can't quite use base64.encodestring() since it tacks on a "courtesy
    # newline".  Blech!
    if not s:
        return s
    value = base64.encodestring(s)
    return value[:-1]


def encode_base64(msg):
    """
    Encode a non-multipart message's payload in Base64 (in place).

    This method modifies the message contents in place and adds or replaces an
    appropriate Content-Transfer-Encoding header.

    :param msg: The non-multipart message to be encoded.
    :type msg: email.message.Message
    """
    encoding = msg.get('Content-Transfer-Encoding', None)
    if encoding is not None:
        encoding = encoding.lower()
    # XXX Python's email module can only decode quoted-printable, base64 and
    # uuencoded data, so we might have to implement other decoding schemes in
    # order to support RFC 3156 properly and correctly calculate signatures
    # for multipart attachments (eg. 7bit or 8bit encoded attachments). For
    # now, if content is already encoded as base64 or if it is encoded with
    # some unknown encoding, we just pass.
    if encoding in [None, 'quoted-printable', 'x-uuencode', 'uue', 'x-uue']:
        orig = msg.get_payload(decode=True)
        encdata = _bencode(orig)
        msg.set_payload(encdata)
        # replace or set the Content-Transfer-Encoding header.
        try:
            msg.replace_header('Content-Transfer-Encoding', 'base64')
        except KeyError:
            msg['Content-Transfer-Encoding'] = 'base64'
    elif encoding is not 'base64':
        logger.error('Unknown content-transfer-encoding: %s' % encoding)


def encode_base64_rec(msg):
    """
    Encode (possibly multipart) messages in base64 (in place).

    This method modifies the message contents in place.

    :param msg: The non-multipart message to be encoded.
    :type msg: email.message.Message
    """
    if not msg.is_multipart():
        encode_base64(msg)
    else:
        for sub in msg.get_payload():
            encode_base64_rec(sub)


#
# RFC 1847: multipart/signed and multipart/encrypted
#

class MultipartSigned(MIMEMultipart):
    """
    Multipart/Signed MIME message according to RFC 1847.

    2.1. Definition of Multipart/Signed

      (1)  MIME type name: multipart
      (2)  MIME subtype name: signed
      (3)  Required parameters: boundary, protocol, and micalg
      (4)  Optional parameters: none
      (5)  Security considerations: Must be treated as opaque while in
           transit

    The multipart/signed content type contains exactly two body parts.
    The first body part is the body part over which the digital signature
    was created, including its MIME headers.  The second body part
    contains the control information necessary to verify the digital
    signature.  The first body part may contain any valid MIME content
    type, labeled accordingly.  The second body part is labeled according
    to the value of the protocol parameter.

    When the OpenPGP digital signature is generated:

    (1)   The data to be signed MUST first be converted to its content-
          type specific canonical form.  For text/plain, this means
          conversion to an appropriate character set and conversion of
          line endings to the canonical <CR><LF> sequence.

    (2)   An appropriate Content-Transfer-Encoding is then applied; see
          section 3.  In particular, line endings in the encoded data
          MUST use the canonical <CR><LF> sequence where appropriate
          (note that the canonical line ending may or may not be present
          on the last line of encoded data and MUST NOT be included in
          the signature if absent).

    (3)   MIME content headers are then added to the body, each ending
          with the canonical <CR><LF> sequence.

    (4)   As described in section 3 of this document, any trailing
          whitespace MUST then be removed from the signed material.

    (5)   As described in [2], the digital signature MUST be calculated
          over both the data to be signed and its set of content headers.

    (6)   The signature MUST be generated detached from the signed data
          so that the process does not alter the signed data in any way.
    """

    def __init__(self, protocol, micalg, boundary=None, _subparts=None):
        """
        Initialize the multipart/signed message.

        :param boundary: the multipart boundary string. By default it is
            calculated as needed.
        :type boundary: str
        :param _subparts: a sequence of initial subparts for the payload. It
            must be an iterable object, such as a list. You can always
            attach new subparts to the message by using the attach() method.
        :type _subparts: iterable
        """
        MIMEMultipart.__init__(
            self, _subtype='signed', boundary=boundary,
            _subparts=_subparts)
        self.set_param('protocol', protocol)
        self.set_param('micalg', micalg)

    def attach(self, payload):
        """
        Add the C{payload} to the current payload list.

        Also prevent from adding payloads with wrong Content-Type and from
        exceeding a maximum of 2 payloads.

        :param payload: The payload to be attached.
        :type payload: email.message.Message
        """
        # second payload's content type must be equal to the protocol
        # parameter given on object creation
        if len(self.get_payload()) == 1:
            if payload.get_content_type() != self.get_param('protocol'):
                raise errors.MultipartConversionError(
                    'Wrong content type %s.' % payload.get_content_type)
        # prevent from adding more payloads
        if len(self._payload) == 2:
            raise errors.MultipartConversionError(
                'Cannot have more than two subparts.')
        MIMEMultipart.attach(self, payload)


class MultipartEncrypted(MIMEMultipart):
    """
    Multipart/encrypted MIME message according to RFC 1847.

    2.2. Definition of Multipart/Encrypted

      (1)  MIME type name: multipart
      (2)  MIME subtype name: encrypted
      (3)  Required parameters: boundary, protocol
      (4)  Optional parameters: none
      (5)  Security considerations: none

    The multipart/encrypted content type contains exactly two body parts.
    The first body part contains the control information necessary to
    decrypt the data in the second body part and is labeled according to
    the value of the protocol parameter.  The second body part contains
    the data which was encrypted and is always labeled
    application/octet-stream.
    """

    def __init__(self, protocol, boundary=None, _subparts=None):
        """
        :param protocol: The encryption protocol to be added as a parameter to
            the Content-Type header.
        :type protocol: str
        :param boundary: the multipart boundary string. By default it is
            calculated as needed.
        :type boundary: str
        :param _subparts: a sequence of initial subparts for the payload. It
            must be an iterable object, such as a list. You can always
            attach new subparts to the message by using the attach() method.
        :type _subparts: iterable
        """
        MIMEMultipart.__init__(
            self, _subtype='encrypted', boundary=boundary,
            _subparts=_subparts)
        self.set_param('protocol', protocol)

    def attach(self, payload):
        """
        Add the C{payload} to the current payload list.

        Also prevent from adding payloads with wrong Content-Type and from
        exceeding a maximum of 2 payloads.

        :param payload: The payload to be attached.
        :type payload: email.message.Message
        """
        # first payload's content type must be equal to the protocol parameter
        # given on object creation
        if len(self._payload) == 0:
            if payload.get_content_type() != self.get_param('protocol'):
                raise errors.MultipartConversionError(
                    'Wrong content type.')
        # second payload is always application/octet-stream
        if len(self._payload) == 1:
            if payload.get_content_type() != 'application/octet-stream':
                raise errors.MultipartConversionError(
                    'Wrong content type %s.' % payload.get_content_type)
        # prevent from adding more payloads
        if len(self._payload) == 2:
            raise errors.MultipartConversionError(
                'Cannot have more than two subparts.')
        MIMEMultipart.attach(self, payload)


#
# RFC 3156: application/pgp-encrypted, application/pgp-signed and
# application-pgp-signature.
#

class PGPEncrypted(MIMEApplication):
    """
    Application/pgp-encrypted MIME media type according to RFC 3156.

      * MIME media type name: application
      * MIME subtype name: pgp-encrypted
      * Required parameters: none
      * Optional parameters: none
    """

    def __init__(self, version=1):
        data = "Version: %d" % version
        MIMEApplication.__init__(self, data, 'pgp-encrypted')


class PGPSignature(MIMEApplication):
    """
    Application/pgp-signature MIME media type according to RFC 3156.

      * MIME media type name: application
      * MIME subtype name: pgp-signature
      * Required parameters: none
      * Optional parameters: none
    """
    def __init__(self, _data, name='signature.asc'):
        MIMEApplication.__init__(self, _data, 'pgp-signature',
                                 _encoder=lambda x: x, name=name)
        self.add_header('Content-Description', 'OpenPGP Digital Signature')


class PGPKeys(MIMEApplication):
    """
    Application/pgp-keys MIME media type according to RFC 3156.

      * MIME media type name: application
      * MIME subtype name: pgp-keys
      * Required parameters: none
      * Optional parameters: none
    """

    def __init__(self, _data):
        MIMEApplication.__init__(self, _data, 'pgp-keys')
