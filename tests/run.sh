#!/bin/sh
set -e
python test.py
python blobs.py
python flags.py
echo "[+] tests ok, no smoke."
