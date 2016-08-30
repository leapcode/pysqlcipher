Leap SMTP Gateway
=================

The Bitmask Client runs a thin SMTP gateway on the user's device, which
intends to encrypt and sign outgoing messages to achieve point to point
encryption.

The gateway is bound to localhost and the user's MUA should be configured to
send messages to it. After doing its thing, the gateway will relay the
messages to the remote SMTP server.

Outgoing mail workflow:

  * SMTP gateway receives a message from the MUA.

  * SMTP gateway queries Key Manager for the user's private key.

  * For each recipient (including addresses in "To", "Cc" anc "Bcc" fields),
    the following happens:

    - The recipient's address is validated against RFC2822.

    - An attempt is made to fetch the recipient's public PGP key.

    - If key is not found:

      - If the gateway is configured to only send encrypted messages the
        recipient is rejected.

      - Otherwise, the message is signed and sent as plain text.

    - If the key is found, the message is encrypted to the recipient and
      signed with the sender's private PGP key.

  * Finally, one message for each recipient is gatewayed to provider's SMTP
    server.


Running tests
-------------

Tests are run using Twisted's Trial API, like this::

    python setup.py test -s leap.mail.gateway.tests
