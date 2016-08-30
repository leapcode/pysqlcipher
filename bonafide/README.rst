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

To run the bonafide service, you can use the bitmask.core daemon. From an
environment in which you have installed the bitmask_core repo::

  bitmaskd

Then you can use `bitmask_cli` to see the available actions, under the user
command.
