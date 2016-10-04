.. Bitmask documentation master file, created by
   sphinx-quickstart on Mon Oct  3 18:23:36 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Bitmask: your internet encryption toolkit
=========================================

Release v\ |version|. (:ref:`Installation <install>` and :ref:`Known Issues
<issues>`)

What is Bitmask?
-----------------------------------------
**Bitmask** is the client for the services offered by `the LEAP Platform`_.  The
services currently deployed are Encrypted Internet Proxy (VPN) and Encrypted Mail.

Bitmask offers a **command-line interface** and a **multiplatform desktop
client**. It can be also used as a **set of libraries** to communicate with the
different services from third party applications.

Bitmask is written in python using `Twisted`_  and licensed under the `GPL3`_. The
Graphical User Interface is written in html+js and uses `PyQt5`_ for serving the
application.

.. _`the LEAP Platform`: https://github.com/leapcode/leap_platform
.. _`Twisted`: https://twistedmatrix.com
.. _`PyQt5`: https://pypi.python.org/pypi/PyQt5
.. _`GPL3`: http://www.gnu.org/licenses/gpl.txt

Understood! Show me the docs!
-----------------------------------------

These documents that you are reading are, mostly, a **guide for developers** that want to contribute to the development of Bitmask, and seek to understand better the code organization and the contribution process.

The **authoritative users guide** lives at `bitmask.net`_.

Other important documents about the LEAP Project can be found at the `Official LEAP documentation`_ site. If you ever need an offline copy, you can clone the `repo for the LEAP Docs site`_. That repo contains also the related LEAP Platform documentation and all the latest design documents. Enhancement contributions and new translations are always welcome! Just open a new merge request.

On the contrary, this developers documentation you are reading right now is maintained in the `bitmask-dev`_ git repo itself, and `can also be checked online`_.

Building the docs
~~~~~~~~~~~~~~~~~

if you want to build these docs locally, you can do::

  make doc

from the topmost folder in the `bitmask-dev`_ repo. Note that you need to have sphinx installed.

.. _`bitmask.net`: https://bitmask.net/
.. _`Official LEAP documentation`: https://leap.se/docs/
.. _`repo for the LEAP Docs site`: https://0xacab.org/leap/leap_se
.. _`bitmask-dev`: https://0xacab.org/leap/bitmask-dev
.. _`can also be checked online`: https://bitmask.readthedocs.io


Contents
--------

.. toctree::
   :maxdepth: 2

   installation/index
   testing/index
   knownissues
   hacking/index
   bundles/index
   cli/index
   core/index
   bonafide/index
   keymanager/index
   mail/index
   changelog
   designdocs/index
   authors

* :ref:`search`

