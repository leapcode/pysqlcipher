Bitmask
===========

*Your internet encryption toolkit*

.. image:: https://badge.fury.io/py/leap.bitmask.svg
    :target: http://badge.fury.io/py/leap.bitmask
.. image:: https://img.shields.io/badge/IRC-leap-blue.svg
   :target: http://webchat.freenode.net/?channels=%23leap&uio=d4
   :alt: IRC
.. image:: https://img.shields.io/badge/IRC-bitmask_(es)-blue.svg
   :target: http://webchat.freenode.net/?channels=%23bitmask-es&uio=d4
   :alt: IRC-es


**Bitmask** is the client for the services offered by `the LEAP Platform`_. It
contains a command-line interface and a multiplatform desktop client. It can be
also used as a set of libraries to communicate with the different services from
third party applications.

It is written in python using `Twisted`_  and licensed under the `GPL3`_. The
Graphical User Interface is written in html+js and uses `PyQt5`_ for serving the
application.

.. _`the LEAP Platform`: https://github.com/leapcode/leap_platform
.. _`Twisted`: https://twistedmatrix.com
.. _`PyQt5`: https://pypi.python.org/pypi/PyQt5
.. _`GPL3`: http://www.gnu.org/licenses/gpl.txt

Read the Docs!
------------------

The latest documentation is available at `LEAP`_.

.. _`LEAP`: https://leap.se/en/docs/client

Bugs
====

Please report any bugs `in our bug tracker`_.

.. _`in our bug tracker`: https://leap.se/code/projects/report-issues 


Development
==============

Tests
-----

You need tox to run the tests. If you don't have it in your system yet::

  pip install tox

And then run all the tests::

  tox

If you are developing against a non-published branch of ``leap.common`` or
``leap.soledad``, run instead::

  tox -e py27-dev

This expects ``leap_common`` and ``soledad`` repos to be checked out in the
parent folder.

Hacking
-------

If you want to develop for the encrypted mail service, execute inside your virtualenv::

  make dev-mail

If you want to develop for the gui client too, you have to have installed the
python2 bindings for Qt5 in your system (in debian: ``apt install python-pyqt5 
python-pyqt5.qtwebkit``). After ensuring this, you can do::

  make dev-all


License
=======

.. image:: https://raw.github.com/leapcode/bitmask_client/develop/docs/user/gpl.png

Bitmask is released under the terms of the `GNU GPL version 3`_ or later.

.. _`GNU GPL version 3`: http://www.gnu.org/licenses/gpl.txt
