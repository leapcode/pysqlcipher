"""
Tests for leap.mail.walk module
"""
import os.path
from email.parser import Parser

from leap.bitmask.mail import walk

CORPUS = {
    'simple': 'rfc822.message',
    'multimin': 'rfc822.multi-minimal.message',
    'multisigned': 'rfc822.multi-signed.message',
    'bounced': 'rfc822.bounce.message',
}

_here = os.path.dirname(__file__)
_parser = Parser()


# tests


def test_simple_mail():
    msg = _parse('simple')
    tree = walk.get_tree(msg)
    assert len(tree['part_map']) == 0
    assert tree['ctype'] == 'text/plain'
    assert tree['multi'] is False


def test_multipart_minimal():
    msg = _parse('multimin')
    tree = walk.get_tree(msg)

    assert tree['multi'] is True
    assert len(tree['part_map']) == 1
    first = tree['part_map'][1]
    assert first['multi'] is False
    assert first['ctype'] == 'text/plain'


def test_multi_signed():
    msg = _parse('multisigned')
    tree = walk.get_tree(msg)
    assert tree['multi'] is True
    assert len(tree['part_map']) == 2

    _first = tree['part_map'][1]
    _second = tree['part_map'][2]
    assert len(_first['part_map']) == 3
    assert(_second['multi'] is False)


def test_bounce_mime():
    msg = _parse('bounced')
    tree = walk.get_tree(msg)

    ctypes = [tree['part_map'][index]['ctype']
              for index in sorted(tree['part_map'].keys())]
    third = tree['part_map'][3]
    three_one_ctype = third['part_map'][1]['ctype']
    assert three_one_ctype == 'multipart/signed'

    assert ctypes == [
        'text/plain',
        'message/delivery-status',
        'message/rfc822']


# utils

def _parse(name):
    _str = _get_string_for_message(name)
    return _parser.parsestr(_str)


def _get_string_for_message(name):
    filename = os.path.join(_here, CORPUS[name])
    with open(filename) as f:
        msgstr = f.read()
    return msgstr
