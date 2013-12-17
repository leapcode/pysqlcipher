#!/bin/bash

#Wraps a command in a virtualenwrapper passed as first argument.
#Example:
#with_virtualenvwrapper.sh leap-bitmask ./run_tests.sh

wd=`pwd`
source `which virtualenvwrapper.sh`
echo "Activating virtualenv " $1
echo "------------------------------------"
workon $1
cd $wd
echo "running version: " `pyver leap.keymanager`
echo "soledad version: " `pyver leap.soledad.common`
$2 $3 $4 $5
