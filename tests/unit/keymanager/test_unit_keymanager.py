from twisted.trial import unittest

from leap.bitmask.keymanager import KeyManager


class KeymanagerTestCase(unittest.TestCase):

    def test_token_propagation(self):
        km = keymanagerFactory()
        assert km._nicknym.token == ''
        km.token = 'sometoken'
        assert km.token == 'sometoken'
        assert km._nicknym.token == 'sometoken'
        km.token = 'othertoken'
        assert km.token == 'othertoken'
        assert km._nicknym.token == 'othertoken'


def keymanagerFactory():

    class DummyKeymanager(KeyManager):
        def _init_gpg(self, soledad, gpg):
            pass

    return DummyKeymanager('foo@localhost', 'localhost', None, token='')
