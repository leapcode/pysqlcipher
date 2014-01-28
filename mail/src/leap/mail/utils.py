# -*- coding: utf-8 -*-
# utils.py
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
Mail utilities.
"""
import json
import re
import traceback

from leap.soledad.common.document import SoledadDocument


CHARSET_PATTERN = r"""charset=([\w-]+)"""
CHARSET_RE = re.compile(CHARSET_PATTERN, re.IGNORECASE)


def first(things):
    """
    Return the head of a collection.
    """
    try:
        return things[0]
    except (IndexError, TypeError):
        return None


def empty(thing):
    """
    Return True if a thing is None or its length is zero.
    """
    if thing is None:
        return True
    if isinstance(thing, SoledadDocument):
        thing = thing.content
    try:
        return len(thing) == 0
    except ReferenceError:
        return True


def maybe_call(thing):
    """
    Return the same thing, or the result of its invocation if it is a
    callable.
    """
    return thing() if callable(thing) else thing


def find_charset(thing, default=None):
    """
    Looks into the object 'thing' for a charset specification.
    It searchs into the object's `repr`.

    :param thing: the object to look into.
    :type thing: object
    :param default: the dafault charset to return if no charset is found.
    :type default: str

    :return: the charset or 'default'
    :rtype: str or None
    """
    charset = first(CHARSET_RE.findall(repr(thing)))
    if charset is None:
        charset = default
    return charset


def lowerdict(_dict):
    """
    Return a dict with the keys in lowercase.

    :param _dict: the dict to convert
    :rtype: dict
    """
    # TODO should properly implement a CaseInsensitive dict.
    # Look into requests code.
    return dict((key.lower(), value)
                for key, value in _dict.items())


class CustomJsonScanner(object):
    """
    This class is a context manager definition used to monkey patch the default
    json string parsing behavior.
    The emails can have more than one encoding, so the `str` objects have more
    than one encoding and json does not support direct work with `str`
    (only `unicode`).
    """

    def _parse_string_str(self, s, idx, *args, **kwargs):
        """
        Parses the string "s" starting at the point idx and returns an `str`
        object. Which basically means it works exactly the same as the regular
        JSON string parsing, except that it doesn't try to decode utf8.
        We need this because mail raw strings might have bytes in multiple
        encodings.

        :param s: the string we want to parse
        :type s: str
        :param idx: the starting point for parsing
        :type idx: int

        :returns: the parsed string and the index where the
                  string ends.
        :rtype: tuple (str, int)
        """
        # NOTE: we just want to use this monkey patched version if we are
        # calling the loads from our custom method. Otherwise, we use the
        # json's default parser.
        monkey_patched = False
        for i in traceback.extract_stack():
            # look for json_loads method in the call stack
            if i[2] == json_loads.__name__:
                monkey_patched = True
                break

        if not monkey_patched:
            return self._orig_scanstring(s, idx, *args, **kwargs)

        found = False
        end = s.find("\"", idx)
        while not found:
            try:
                if s[end-1] != "\\":
                    found = True
                else:
                    end = s.find("\"", end+1)
            except Exception:
                found = True
        return s[idx:end].decode("string-escape"), end+1

    def __enter__(self):
        """
        Replace the json methods with the needed ones.
        Also make a backup to restore them later.
        """
        # backup original values
        self._orig_make_scanner = json.scanner.make_scanner
        self._orig_scanstring = json.decoder.scanstring

        # We need the make_scanner function to be the python one so we can
        # monkey_patch the json string parsing
        json.scanner.make_scanner = json.scanner.py_make_scanner

        # And now we monkey patch the money method
        json.decoder.scanstring = self._parse_string_str

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Restores the backuped methods.
        """
        # restore original values
        json.scanner.make_scanner = self._orig_make_scanner
        json.decoder.scanstring = self._orig_scanstring


def json_loads(data):
    """
    It works as json.loads but supporting multiple encodings in the same
    string and accepting an `str` parameter that won't be converted to unicode.

    :param data: the string to load the objects from
    :type data: str

    :returns: the corresponding python object result of parsing 'data', this
              behaves similarly as json.loads, with the exception of that
              returns always `str` instead of `unicode`.
    """
    obj = None
    with CustomJsonScanner():
        # We need to use the cls parameter in order to trigger the code
        # that will let us control the string parsing method.
        obj = json.loads(data, cls=json.JSONDecoder)

    return obj
