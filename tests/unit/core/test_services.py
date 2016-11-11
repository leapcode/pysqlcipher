from twisted.internet import defer
from twisted.trial import unittest

from leap.bitmask.core.mail_services import KeymanagerService


class KeymanagerServiceTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def test_keymanager_service_list_call(self):
        kms = keymanagerServiceFactory()
        yield kms.do_list_keys({'user': 'user'})
        assert kms._keymanager.loopback == ['get_all_keys']

    @defer.inlineCallbacks
    def test_keymanager_service_export_call(self):
        kms = keymanagerServiceFactory()
        yield kms.do_export({'user': 'user'}, 'foo@bar')
        assert kms._keymanager.loopback == ['get_key']

    @defer.inlineCallbacks
    def test_keymanager_service_insert_call(self):
        kms = keymanagerServiceFactory()
        yield kms.do_insert({'user': 'user'}, 'foo@bar', 'aaaa')
        assert kms._keymanager.loopback == ['put_raw_key', 'get_key']

    @defer.inlineCallbacks
    def test_keymanager_service_delete_call(self):
        kms = keymanagerServiceFactory()
        yield kms.do_delete({'user': 'user'}, 'foo@bar')
        assert kms._keymanager.loopback == ['get_key', 'delete_key']


class _container(object):

    class _keymanager(object):
        """
        This implements the basic public contract of the Keymanager object,
        just to mock the calls made from the KemanagerService.
        """
        def __init__(self):
            self.loopback = []

        def get_all_keys(self, private=False):
            self.loopback.append('get_all_keys')
            return defer.succeed([])

        def get_key(self, address, private=False, fetch_remote=False):
            self.loopback.append('get_key')

            class _key(dict):
                fingerprint = 'deadbeef'
            return defer.succeed(_key())

        def put_raw_key(self, rawkey, address, validation=""):
            self.loopback.append('put_raw_key')
            return defer.succeed('')

        def delete_key(self, key):
            self.loopback.append('delete_key')
            return defer.succeed('')

    def __init__(self):
        self._instances = {'user': self._keymanager()}

    def get_instance(self, userid):
        return self._instances.get(userid)


def keymanagerServiceFactory():
    kms = KeymanagerService()
    kms._container = _container()
    kms._keymanager = kms._container.get_instance('user')
    return kms
