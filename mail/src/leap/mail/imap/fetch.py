import json

from twisted.python import log

from leap.common.check import leap_assert, leap_assert_type
from leap.soledad import Soledad

from leap.common.keymanager import openpgp


class LeapIncomingMail(object):
    """
    Fetches mail from the incoming queue.
    """
    def __init__(self, keymanager, soledad, imap_account):

        """
        Initialize LeapIMAP.

        :param keymanager: a keymanager instance
        :type keymanager: keymanager.KeyManager

        :param soledad: a soledad instance
        :type soledad: Soledad

        :param imap_account: the account to fetch periodically
        :type imap_account: SoledadBackedAccount
        """

        leap_assert(keymanager, "need a keymanager to initialize")
        leap_assert_type(soledad, Soledad)

        self._keymanager = keymanager
        self._soledad = soledad
        self.imapAccount = imap_account

        self._pkey = self._keymanager.get_all_keys_in_local_db(
            private=True).pop()

    def fetch(self):
        """
        Get new mail by syncing database, store it in the INBOX for the
        user account, and remove from the incoming db.
        """
        self._soledad.sync()
        gen, doclist = self._soledad.get_all_docs()
        #log.msg("there are %s docs" % (len(doclist),))

        if doclist:
            inbox = self.imapAccount.getMailbox('inbox')

        key = self._pkey
        for doc in doclist:
            keys = doc.content.keys()
            if '_enc_scheme' in keys and '_enc_json' in keys:

                # XXX should check for _enc_scheme == "pubkey" || "none"
                # that is what incoming mail uses.

                encdata = doc.content['_enc_json']
                decrdata = openpgp.decrypt_asym(
                    encdata, key,
                    # XXX get from public method instead
                    passphrase=self._soledad._passphrase)
                if decrdata:
                    self.process_decrypted(doc, decrdata, inbox)
        # XXX launch sync callback / defer

    def process_decrypted(self, doc, data, inbox):
        """
        Process a successfully decrypted message
        """
        log.msg("processing incoming message!")
        msg = json.loads(data)
        if not isinstance(msg, dict):
            return False
        if not msg.get('incoming', False):
            return False
        # ok, this is an incoming message
        rawmsg = msg.get('content', None)
        if not rawmsg:
            return False
        #log.msg("we got raw message")

        # add to inbox and delete from soledad
        inbox.addMessage(rawmsg, ("\\Recent",))
        doc_id = doc.doc_id
        self._soledad.delete_doc(doc)
        log.msg("deleted doc %s from incoming" % doc_id)
