# -*- coding: utf-8 -*-
# setup.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
setup file for leap.keymanager
"""
from setuptools import setup
from setuptools import find_packages

import versioneer
versioneer.versionfile_source = 'src/leap/keymanager/_version.py'
versioneer.versionfile_build = 'leap/keymanager/_version.py'
versioneer.tag_prefix = ''  # tags are like 1.2.0
versioneer.parentdir_prefix = 'leap.keymanager-'

from pkg import utils

trove_classifiers = [
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Topic :: Communications :: Email',
    'Topic :: Internet',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries',
]

# XXX add ref to docs

setup(
    name='leap.keymanager',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    url='https://leap.se/',
    license='GPLv3+',
    description='LEAP\'s Key Manager',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    long_description=(
        "The Key Manager handles all types of keys to allow for "
        "point-to-point encryption between parties communicating through "
        "LEAP infrastructure."
    ),
    classifiers=trove_classifiers,
    namespace_packages=["leap"],
    packages=find_packages('src', exclude=['leap.keymanager.tests']),
    package_dir={'': 'src'},
    test_suite='leap.keymanager.tests',
    install_requires=utils.parse_requirements(),
    tests_require=utils.parse_requirements(
        reqfiles=['pkg/requirements-testing.pip']),
)
