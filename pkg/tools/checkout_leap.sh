#!/bin/sh
if [ ! -d "../leap_commondev" ]; then
	git clone https://github.com/leapcode/leap_pycommon ../leap_commondev
fi
if [ ! -d "../soledaddev" ]; then
	git clone https://github.com/leapcode/soledad ../soledaddev
fi
cd ../leap_commondev && git checkout master && git pull origin master
cd ../soledaddev && git checkout develop && git pull origin develop
