#!/bin/sh
# Watchout! this will need much manual touches
# to the generated apidocs. Mainly: s/mail/leap.mail/g
sphinx-apidoc -M -o api ../src/leap/mail
