leap.mail
=========
Mail services for the LEAP Client.

.. image:: https://badge.fury.io/py/leap.mail.svg
    :target: http://badge.fury.io/py/leap.mail

.. image:: https://readthedocs.org/projects/leapmail/badge/?version=latest
         :target: http://leapmail.readthedocs.org/en/latest/
         :alt: Documentation Status

More info: https://leap.se

running tests
-------------

Use trial to run the test suite::

  trial leap.mail

... and all its goodies. To run all imap tests in a loop until some of them
fails::

  trial -u leap.mail.imap

Read the *trial* manpage for more options .

imap regressions
----------------

For testing the IMAP server implementation, there are a couple of utilities.
From the ``leap.mail.imap.tests`` folder, and with an already initialized server
running::

  ./regressions_mime_struct user@provider pass path_to_samples/

You can find several message samples in the ``leap/mail/tests`` folder.
