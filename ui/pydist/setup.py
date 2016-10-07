#!/usr/bin/env python
# -*- coding: utf-8 -*-
# setup.py
# Copyright (C) 2016 LEAP Encryption Acess Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Setup file for bitmask_js
"""

from setuptools import setup
import datetime
import time

long_description = '''leap.bitmask_js
-----------------
This package contains the already compiled javascript resources for the bitmask
UI.

If you want to develop for this UI, please checkout the bitmask-dev [0] repo
and follow the instructions in the ui/README.md file.

[0] https://github.com/leapcode/bitmask-dev'''

now = datetime.datetime.now()
timestamp = time.strftime('%Y%m%d%H%M', now.timetuple())

setup(
    name='leap.bitmask_js',
    version='0.1.%s' % timestamp,
    description='Bitmask UI',
    long_description=long_description,
    author='LEAP Encrypted Access Project',
    author_email='info@leap.se',
    namespace_packages=['leap'],
    url='http://leap.se',
    packages=['leap.bitmask_js'],
    package_data={
        '': ['public/*',
             'public/css/*',
             'public/fonts/*',
             'public/img/*',
             'public/js/*',
             ]
    }
)
