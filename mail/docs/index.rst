.. leap.mail documentation master file, created by
   sphinx-quickstart on Mon Aug 25 19:19:48 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to leap.mail's documentation!
=====================================

This is the documentation for the ``leap.mail`` module. It is a twisted package
that exposes two services, ``smtp`` and ``imap``, that run local proxies and interact
with a remote ``LEAP`` provider that offers *a soledad syncronization endpoint*
and receive the outgoing email.

See :ref:`the life cycle of a leap email <mail_journey>` for an overview of the life cycle
of an email through ``LEAP`` providers.

``Soledad`` stores its documents as local ``sqlcipher`` tables, and syncs
against the soledad sync service in the provider.


.. TODO clear document types documentation.

The data model at the present moment consists of several *document types* that split email into
different documents that are stored in ``Soledad``. The idea behind this is to
keep clear the separation between *mutable* and *inmutable* parts, and still being able to
reconstruct arbitrarily nested email structures easily.

In the coming releases we are going to be working towards the goal of exposing
a protocol-agnostic email public API, so that third party mail clients can
manipulate the data layer without having to resort to handling the sql tables or
doing direct u1db calls. The code will be transitioning towards a LEAPMail
public API that we can stabilize as soon as possible, and leaving the IMAP
server as another code entity that uses this lower layer.


..
.. Contents:
.. toctree::
   :maxdepth: 2

..   intro
..   tutorial


API documentation
-----------------

If you were looking for the documentation of the ``leap.mail`` module, you will
find it here. Beware that the public API will still be unstable for the next
development cycles.

.. toctree::
   :maxdepth: 2

   api/mail




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

