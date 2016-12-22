#!/bin/bash

set -x
set -e

PROVIDER='cdev.bitmask.net'
BCTL='bitmaskctl'
LEAP_HOME='~/.config/leap'
username="tmp_user_$(date +%Y%m%d%H%M%S)"
user="${username}@${PROVIDER}"
pw="$(head -c 10 < /dev/urandom | base64)"

# Stop any previously started bitmaskd
# and start a new instance
"$BCTL" stop

rm -rf $LEAP_HOME

"$BCTL" start


# Register a new user
"$BCTL" user create "$user" --pass "$pw"

# Authenticate
"$BCTL" user auth "$user" --pass "$pw"

# Note that imap_pw is the same for smtp

imap_pw="None"

# FIXME -- this would be prettier if we had the auth command block on
# the first-time run, so that we just return when the key has been generated
# and explicitely raise any error found

while [[ $imap_pw == *"None"* ]]; do
  response=$("$BCTL" mail get_token)
  sleep 2
  imap_pw=$(echo $response | head -n 1 | sed 's/  */ /g' | cut -d' ' -f 2)
done

echo "IMAP/SMTP PASSWD: $imap_pw"
