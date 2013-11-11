Leap SMTP Gateway
=================

Outgoing mail workflow:

    * LEAP client runs a thin SMTP proxy on the user's device, bound to
      localhost.
    * User's MUA is configured outgoing SMTP to localhost.
    * When SMTP proxy receives an email from MUA:
        * SMTP proxy queries Key Manager for the user's private key and public
          keys of all recipients.
        * Message is signed by sender and encrypted to recipients.
        * If recipient's key is missing, email goes out in cleartext (unless
          user has configured option to send only encrypted email).
        * Finally, message is gatewayed to provider's SMTP server.


Running tests
-------------

Tests are run using Twisted's Trial API, like this::

    python setup.py test -s leap.mail.gateway.tests
