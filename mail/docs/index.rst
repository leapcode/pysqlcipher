.. leap.mail documentation master file, created by
   sphinx-quickstart on Mon Aug 25 19:19:48 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

leap.mail
=========

*decentralized and secure mail delivery and synchronization*

This is the documentation for the ``leap.mail`` module. It is a `twisted`_
package that allows to receive, process, send and access existing messages using
the `LEAP`_ platform.

One way to use this library is to let it launch two standard mail services,
``smtp`` and ``imap``, that run as local proxies and interact with a remote
``LEAP`` provider that offers *a soledad syncronization endpoint* and receives 
the outgoing email. This is what `Bitmask`_ client does.

From the release 0.4.0 on, it's also possible to use a protocol-agnostic email
public API, so that third party mail clients can manipulate the data layer. This
is what the awesome MUA in the `Pixelated`_ project is using.

.. _`twisted`: https://twistedmatrix.com/trac/
.. _`LEAP`: https://leap.se/en/docs
.. _`Bitmask`: https://bitmask.net/en/features#email
.. _`Pixelated`: https://pixelated-project.org/

How does this all work?
-----------------------

All the underlying data storage and sync is handled by a library called
`soledad`_, which handles encryption, storage and sync. Based on `u1db`_,
documents are stored locally as local ``sqlcipher`` tables, and syncs against
the soledad sync service in the provider.

OpenPGP key generation and keyring management are handled by another leap
python library: `keymanager`_.

See :ref:`the life cycle of a leap email <mail_journey>` for an overview of the life cycle
of an email through ``LEAP`` providers.

.. _`Soledad`: https://leap.se/en/docs/design/soledad
.. _`u1db`: https://en.wikipedia.org/wiki/U1DB
.. _`keymanager`: https://github.com/leapcode/keymanager/


Data model
----------
.. TODO clear document types documentation.

The data model at the present moment consists of several *document types* that split email into
different documents that are stored in ``Soledad``. The idea behind this is to
keep clear the separation between *mutable* and *inmutable* parts, and still being able to
reconstruct arbitrarily nested email structures easily.

Documentation index
===================

..
.. Contents:
.. toctree::
   :maxdepth: 2

   hacking

..   intro
..   tutorial


API documentation
-----------------

If you were looking for the documentation of the ``leap.mail`` module, you will
find it here.

Of special interest is the `public mail api`_, which should remain relatively
stable across the next few releases.

.. _`public mail api`: api/mail.html#module-mail


.. toctree::
   :maxdepth: 2

   api/leap.mail



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

