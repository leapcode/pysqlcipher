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
from email.utils import parseaddr
import json
import re
import traceback
import Queue

from leap.soledad.common.document import SoledadDocument
from leap.common.check import leap_assert_type
from twisted.mail import smtp


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
    If thing is a number (int, float, long), return False.
    """
    if thing is None:
        return True
    if isinstance(thing, (int, float, long)):
        return False
    if isinstance(thing, SoledadDocument):
        thing = thing.content
    try:
        return len(thing) == 0
    except (ReferenceError, TypeError):
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


PART_MAP = "part_map"
PHASH = "phash"


def _str_dict(d, k):
    """
    Convert the dictionary key to string if it was a string.

    :param d: the dict
    :type d: dict
    :param k: the key
    :type k: object
    """
    if isinstance(k, int):
        val = d[k]
        d[str(k)] = val
        del(d[k])


def stringify_parts_map(d):
    """
    Modify a dictionary making all the nested dicts under "part_map" keys
    having strings as keys.

    :param d: the dictionary to modify
    :type d: dictionary
    :rtype: dictionary
    """
    for k in d:
        if k == PART_MAP:
            pmap = d[k]
            for kk in pmap.keys():
                _str_dict(d[k], kk)
            for kk in pmap.keys():
                stringify_parts_map(d[k][str(kk)])
    return d


def phash_iter(d):
    """
    A recursive generator that extracts all the payload-hashes
    from an arbitrary nested parts-map dictionary.

    :param d: the dictionary to walk
    :type d: dictionary
    :return: a list of all the phashes found
    :rtype: list
    """
    if PHASH in d:
        yield d[PHASH]
    if PART_MAP in d:
        for key in d[PART_MAP]:
            for phash in phash_iter(d[PART_MAP][key]):
                yield phash


def accumulator(fun, lim):
    """
    A simple accumulator that uses a closure and a mutable
    object to collect items.
    When the count of items is greater than `lim`, the
    collection is flushed after invoking a map of the function `fun`
    over it.

    The returned accumulator can also be flushed at any moment
    by passing a boolean as a second parameter.

    :param fun: the function to call over the collection
                when its size is greater than `lim`
    :type fun: callable
    :param lim: the turning point for the collection
    :type lim: int
    :rtype: function

    >>> from pprint import pprint
    >>> acc = accumulator(pprint, 2)
    >>> acc(1)
    >>> acc(2)
    [1, 2]
    >>> acc(3)
    >>> acc(4)
    [3, 4]
    >>> acc = accumulator(pprint, 5)
    >>> acc(1)
    >>> acc(2)
    >>> acc(3)
    >>> acc(None, flush=True)
    [1,2,3]
    """
    KEY = "items"
    _o = {KEY: []}

    def _accumulator(item, flush=False):
        collection = _o[KEY]
        collection.append(item)
        if len(collection) >= lim or flush:
            map(fun, filter(None, collection))
            _o[KEY] = []

    return _accumulator


def accumulator_queue(fun, lim):
    """
    A version of the accumulator that uses a queue.

    When the count of items is greater than `lim`, the
    queue is flushed after invoking the function `fun`
    over its items.

    The returned accumulator can also be flushed at any moment
    by passing a boolean as a second parameter.

    :param fun: the function to call over the collection
                when its size is greater than `lim`
    :type fun: callable
    :param lim: the turning point for the collection
    :type lim: int
    :rtype: function
    """
    _q = Queue.Queue()

    def _accumulator(item, flush=False):
        _q.put(item)
        if _q.qsize() >= lim or flush:
            collection = [_q.get() for i in range(_q.qsize())]
            map(fun, filter(None, collection))

    return _accumulator


def validate_address(address):
    """
    Validate C{address} as defined in RFC 2822.

    :param address: The address to be validated.
    :type address: str

    @return: A valid address.
    @rtype: str

    @raise smtp.SMTPBadRcpt: Raised if C{address} is invalid.
    """
    leap_assert_type(address, str)
    # in the following, the address is parsed as described in RFC 2822 and
    # ('', '') is returned if the parse fails.
    _, address = parseaddr(address)
    if address == '':
        raise smtp.SMTPBadRcpt(address)
    return address

#
# String manipulation
#


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

        # TODO profile to see if a compiled regex can get us some
        # benefit here.
        found = False
        end = s.find("\"", idx)
        while not found:
            try:
                if s[end - 1] != "\\":
                    found = True
                else:
                    end = s.find("\"", end + 1)
            except Exception:
                found = True
        return s[idx:end].decode("string-escape"), end + 1

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


class CaseInsensitiveDict(dict):
    """
    A dictionary subclass that will allow case-insenstive key lookups.
    """
    def __init__(self, d=None):
        if d is None:
            d = []
        if isinstance(d, dict):
            for key, value in d.items():
                self[key] = value
        else:
            for key, value in d:
                self[key] = value

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())
