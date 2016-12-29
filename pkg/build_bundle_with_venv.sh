#!/bin/bash
###########################################################
# Build a Bitmask bundle inside a fresh virtualenv.
# To be run by Gitlab Runner,
# will produce an artifact for each build.
###########################################################
virtualenv venv
source venv/bin/activate
$VIRTUAL_ENV/bin/pip install -U pyinstaller==3.1 packaging
$VIRTUAL_ENV/bin/pip install zope.interface zope.proxy

# For the Bitmask 0.9.4 bundles.
$VIRTUAL_ENV/bin/pip install -U leap.soledad.common==0.9.1
$VIRTUAL_ENV/bin/pip install -U leap.soledad.client==0.9.1

# CHANGE THIS IF YOU WANT A DIFFERENT BRANCH CHECKED OUT FOR COMMON/SOLEDAD --------------------
# (this is tracking shyba/feature/streaming_encrypter for the moment)
# $VIRTUAL_ENV/bin/pip install -U leap.soledad.common --find-links https://devpi.net/kali/dev 
# $VIRTUAL_ENV/bin/pip install -U leap.soledad.client --find-links https://devpi.net/kali/dev 
# ----------------------------------------------------------------------------------------------

# XXX hack for the namespace package not being properly handled by pyinstaller
touch $VIRTUAL_ENV/lib/python2.7/site-packages/zope/__init__.py
touch $VIRTUAL_ENV/lib/python2.7/site-packages/leap/soledad/__init__.py

make dev-all

$VIRTUAL_ENV/bin/pip uninstall leap.bitmask
$VIRTUAL_ENV/bin/pip install .

make bundle
make bundle_gpg
