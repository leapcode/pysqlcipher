:LastChangedDate: $LastChangedDate$
:LastChangedRevision: $LastChangedRevision$
:LastChangedBy: $LastChangedBy$

Hacking
=================================
blah blah

Running tests
---------------------------------

Tox is all you need::

  tox

Test when changes are made to common/soledad
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are developing against a non-published branch of ``leap.common`` or
``leap.soledad``, run instead::

  tox -e py27-dev

This expects ``leap_common`` and ``soledad`` repos to be checked out in the
parent folder.

Setting up the development environment
--------------------------------------

Dependencies::

  sudo apt install build-essential python-virtualenv libsqlcipher-dev \
        libssl-dev libffi-dev

There are different requirements files::

  ...

How to contribute
---------------------------------

Merge requests to https://0xacab/leap/bitmask-dev

Coding conventions
---------------------------------
* pep8
* Git messages should be informative.
* There is a pre-commit hook ready to be used in the ``docs/hooks`` folder,
  alongside some other hooks to do autopep8 on each commit.

.. include:: ../hooks/leap-commit-template.README
   :literal:

Pinning
----------------------------------
Only in the requirements files.

Signing your commits
---------------------------------
* For contributors with commit access

Developing on the gui
---------------------------------
blah blah. see some other README

Developing on the Javascript UI
---------------------------------
blah blah. see the main README

Developing on the Thunderbird Extension
---------------------------------------
blah blah

Making a new release
--------------------
A checklist for the release process can be found :ref:`here <release>`

Contribution ideas
------------------
Want to help?

Some areas in which we always need contribution are:

* Localization of the client (talk to elijah).
* Multiplatform gitlab runners
* Windows and OSX packaging
* Windows Firewall integration for VPN
* Migrating components to py3 (look for vshyba or kali).
