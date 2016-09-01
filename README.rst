bitmask-dev
===========
**Your internet encryption toolkit**

Develop
-------

If you want to develop for the encrypted mail service, execute inside your virtualenv::

  make dev-mail

If you want to develop for the gui client too, you have to have installed the
python2 bindings for Qt5 in your system (in debian is python-pyqt5). After
ensuring this, you can do::

  make dev-all

Tests
-----

Tests need tox::

  pip install tox
  tox

If you are developing against a non-published branch of leap.common or
leap.soledad, run instead::

  tox -e py27-dev
