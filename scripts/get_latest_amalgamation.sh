#!/bin/sh
# author: drebs@leap.se

# Get SQLCipher amalgamation files from latest tag from git repository.
#
# We want latest so we can build SQLCipher with JSON1 support:
# https://www.sqlite.org/json1.html

SQLCIPHER_REPO="https://github.com/sqlcipher/sqlcipher"

if [ $# -ne 1 ]; then
    echo "Usage: ${0} AMALGAMATION_ROOT"
    exit 1
fi

TEMP_DIR=`mktemp -d`
REPO_DIR="${TEMP_DIR}/sqlcipher"
SCRIPT_DIR=`pwd`
AMALGAMATION_ROOT=${1}
AMALGAMATION_DIR="${SCRIPT_DIR}/${AMALGAMATION_ROOT}"

# clone, checkout latest tag and build amalgamation
git clone ${SQLCIPHER_REPO} ${REPO_DIR}
(cd ${REPO_DIR} \
  && git checkout `git tag | tail -n 1` \
  && ./configure \
  && make sqlite3.c)

# make sure old files are wiped from amalgamation dir
if [ -d ${AMALGAMATION_DIR} ]; then
    rm -rf ${AMALGAMATION_DIR}/*
else
    mkdir -p ${AMALGAMATION_DIR}
fi

# copy amalgamation files
cp ${REPO_DIR}/sqlite3.{c,h} ${AMALGAMATION_DIR}/

# remove leftovers
rm -rf ${TEMP_DIR}
