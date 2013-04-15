import json
import os
#import hmac

from xdg import BaseDirectory

from twisted.python import log

from leap.common.check import leap_assert
from leap.soledad import Soledad

from leap.common.keymanager import openpgp


class LeapIncomingMail(object):
    """
    Fetches mail from the incoming queue.
    """
    def __init__(self, keymanager, user_uuid, soledad_pass, server_url,
                 server_pemfile, token, imap_account,
                 **kwargs):
        """
        Initialize LeapIMAP.

        :param user: The user adress in the form C{user@provider}.
        :type user: str

        :param soledad_pass: The password for the local database replica.
        :type soledad_pass: str

        :param server_url: The URL of the remote server to sync against.
        :type couch_url: str

        :param server_pemfile: The pemfile for the remote sync server TLS
                               handshake.
        :type server_pemfile: str

        :param token: a session token valid for this user.
        :type token: str

        :param imap_account: a SoledadBackedAccount instance to which
                             the incoming mail will be saved to

        :param **kwargs: Used to pass arguments to Soledad instance. Maybe
            Soledad instantiation could be factored out from here, and maybe
            we should have a standard for all client code.
        """
        leap_assert(user_uuid, "need an user uuid to initialize")

        self._keymanager = keymanager
        self._user_uuid = user_uuid
        self._server_url = server_url
        self._soledad_pass = soledad_pass

        base_config = BaseDirectory.xdg_config_home
        secret_path = os.path.join(
            base_config, "leap", "soledad", "%s.secret" % user_uuid)
        soledad_path = os.path.join(
            base_config, "leap", "soledad", "%s-incoming.u1db" % user_uuid)

        self.imapAccount = imap_account
        self._soledad = Soledad(
            user_uuid,
            soledad_pass,
            secret_path,
            soledad_path,
            server_url,
            server_pemfile,
            token,
            bootstrap=True)

        self._pkey = self._keymanager.get_all_keys_in_local_db(
            private=True).pop()
        log.msg('fetcher got soledad instance')

    def fetch(self):
        """
        Get new mail by syncing database, store it in the INBOX for the
        user account, and remove from the incoming db.
        """
        self._soledad.sync()

        #log.msg('getting all docs')
        gen, doclist = self._soledad.get_all_docs()
        #log.msg("there are %s docs" % (len(doclist),))

        if doclist:
            inbox = self.imapAccount.getMailbox('inbox')

        #import ipdb; ipdb.set_trace()

        key = self._pkey
        for doc in doclist:
            keys = doc.content.keys()
            if '_enc_scheme' in keys and '_enc_json' in keys:

                # XXX should check for _enc_scheme == "pubkey" || "none"
                # that is what incoming mail uses.

                encdata = doc.content['_enc_json']
                decrdata = openpgp.decrypt_asym(
                    encdata, key,
                    passphrase=self._soledad_pass)
                if decrdata:
                    self.process_decrypted(doc, decrdata, inbox)
        # XXX launch sync callback

    def process_decrypted(self, doc, data, inbox):
        """
        Process a successfully decrypted message
        """
        log.msg("processing message!")
        msg = json.loads(data)
        if not isinstance(msg, dict):
            return False
        if not msg.get('incoming', False):
            return False
        # ok, this is an incoming message
        rawmsg = msg.get('content', None)
        if not rawmsg:
            return False
        log.msg("we got raw message")

        # add to inbox and delete from soledad
        inbox.addMessage(rawmsg, ("\\Recent",))
        log.msg("added msg")
        self._soledad.delete_doc(doc)
        log.msg("deleted doc")
