#!/bin/bash
virtualenv venv
source venv/bin/activate
$VIRTUAL_ENV/bin/pip install -U pyinstaller==3.1 packaging
$VIRTUAL_ENV/bin/pip install zope.interface zope.proxy
$VIRTUAL_ENV/bin/pip install leap.soledad.common
$VIRTUAL_ENV/bin/pip install leap.soledad.client

# XXX hack for the namespace package not being properly handled by pyinstaller
touch $VIRTUAL_ENV/lib/python2.7/site-packages/zope/__init__.py
touch $VIRTUAL_ENV/lib/python2.7/site-packages/leap/soledad/__init__.py

make dev-all

$VIRTUAL_ENV/bin/pip uninstall leap.bitmask
$VIRTUAL_ENV/bin/pip install .

make bundle
