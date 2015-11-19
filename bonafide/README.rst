Bonafide
========
Bonafide is the protocol for secure user registration, authentication, and provider discovery for the LEAP
applications. See the `Bonafide`_ design docs.

This is a client implementation, written in python. It consists of a python library, a
twisted service and a command-line interface to interact locally with it.

.. _`Bonafide`: https://leap.se/en/docs/design/bonafide

Using
-----

This is still in development. To play with it, create a virtualenv, and deploy
the package in development mode by running::

  python setup.py develop

from the parent folder.

To run the bonafide daemon::

  make bonafide_server

Then you can use `bonafide_cli2 -h` to see the available commands.
