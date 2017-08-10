#!/bin/sh
set -e
rm -f test.db blobs.db
python test.py
python blobs.py
python flags.py
echo "[+] tests ok, no smoke."
