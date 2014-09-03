from twisted.protocols import loopback
from twisted.python import util

from leap.mail.imap.tests.utils import IMAP4HelperMixin

TEST_USER = "testuser@leap.se"
TEST_PASSWD = "1234"


class StoreAndFetchTestCase(IMAP4HelperMixin):
    """
    Several tests to check that the internal storage representation
    is able to render the message structures as we expect them.
    """

    def setUp(self):
        IMAP4HelperMixin.setUp(self)
        self.received_messages = self.received_uid = None
        self.result = None

    def addListener(self, x):
        pass

    def removeListener(self, x):
        pass

    def _addSignedMessage(self, _):
        self.server.state = 'select'
        infile = util.sibpath(__file__, 'rfc822.multi-signed.message')
        raw = open(infile).read()
        MBOX_NAME = "multipart/SIGNED"

        self.server.theAccount.addMailbox(MBOX_NAME)
        mbox = self.server.theAccount.getMailbox(MBOX_NAME)
        self.server.mbox = mbox
        # return a deferred that will fire with UID
        return self.server.mbox.messages.add_msg(raw)

    def _fetchWork(self, uids):

        def result(R):
            self.result = R

        self.connected.addCallback(
            self._addSignedMessage).addCallback(
            lambda uid: self.function(
                uids, uid=uid)  # do NOT use seq numbers!
            ).addCallback(result).addCallback(
            self._cbStopClient).addErrback(self._ebGeneral)

        d = loopback.loopbackTCP(self.server, self.client, noisy=False)
        d.addCallback(lambda x: self.assertEqual(self.result, self.expected))
        return d

    def testMultiBody(self):
        """
        Test that a multipart signed message is retrieved the same
        as we stored it.
        """
        self.function = self.client.fetchBody
        messages = '1'

        # XXX review. This probably should give everything?

        self.expected = {1: {
            'RFC822.TEXT': 'This is an example of a signed message,\n'
                           'with attachments.\n\n\n--=20\n'
                           'Nihil sine chao! =E2=88=B4\n',
            'UID': '1'}}
        # print "test multi: fetch uid", messages
        return self._fetchWork(messages)
