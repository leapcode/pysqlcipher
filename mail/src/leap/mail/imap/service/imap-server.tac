import ConfigParser
import os

from xdg import BaseDirectory

from leap.soledad.client import Soledad
from leap.mail.imap.service import imap


config = ConfigParser.ConfigParser()
config.read([os.path.expanduser('~/.config/leap/mail/mail.conf')])

userID = config.get('mail', 'address')
privkey = open(os.path.expanduser('~/.config/leap/mail/privkey')).read()
nickserver_url = ""

d = {}

for key in ('uid', 'passphrase', 'server', 'pemfile', 'token'):
    d[key] = config.get('mail', key)


def initialize_soledad_mailbox(user_uuid, soledad_pass, server_url,
                               server_pemfile, token):
    """
    Initializes soledad by hand

    :param user_uuid:
    :param soledad_pass:
    :param server_url:
    :param server_pemfile:
    :param token:

    :rtype: Soledad instance
    """

    base_config = BaseDirectory.xdg_config_home

    secret_path = os.path.join(
        base_config, "leap", "soledad", "%s.secret" % user_uuid)
    soledad_path = os.path.join(
        base_config, "leap", "soledad", "%s-mailbox.db" % user_uuid)

    _soledad = Soledad(
        user_uuid,
        soledad_pass,
        secret_path,
        soledad_path,
        server_url,
        server_pemfile,
        token)

    return _soledad

soledad = initialize_soledad_mailbox(
    d['uid'],
    d['passphrase'],
    d['server'],
    d['pemfile'],
    d['token'])

# import the private key ---- should sync it from remote!
from leap.common.keymanager.openpgp import OpenPGPScheme
opgp = OpenPGPScheme(soledad)
opgp.put_ascii_key(privkey)

from leap.common.keymanager import KeyManager
keymanager = KeyManager(userID, nickserver_url, soledad, d['token'])

imap.run_service(soledad, keymanager)
