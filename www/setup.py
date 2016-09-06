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
Setup file for leap.bitmask-www
"""

from setuptools import setup

import datetime
import time


# TODO  add all the node steps in this setup too.
# Right now it's expected that you run the node commands by hand
# i.e., 'make build'

now = datetime.datetime.now()
timestamp = time.strftime('%Y%m%d', now.timetuple())

setup(
    name='leap.bitmask_www',
    version='0.1.%s' % timestamp,
    description='Bitmask html/js UI',
    long_description=open('notes-python.txt').read(),
    author='LEAP Encrypted Access Project',
    author_email='info@leap.se',
    url='http://leap.se',
    namespace_packages=['leap'],
    packages=['leap.bitmask_www'],
    package_data={
        '': ['public/*',
             'public/css/*',
             'public/fonts/*',
             'public/img/*',
             'publlic/js/*',
             ]
    }
)
