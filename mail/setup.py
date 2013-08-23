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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
setup file for leap.mail
"""
from setuptools import setup
from setuptools import find_packages

import versioneer
versioneer.versionfile_source = 'src/leap/mail/_version.py'
versioneer.versionfile_build = 'leap/mail/_version.py'
versioneer.tag_prefix = ''  # tags are like 1.2.0
versioneer.parentdir_prefix = 'leap.mail-'

from pkg import utils

trove_classifiers = [
    'Development Status :: 4 - Beta',
    'Framework :: Twisted',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License '
    'v3 (GPLv3)',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Topic :: Communications :: Email',
    'Topic :: Communications :: Email :: Post-Office :: IMAP',
    'Topic :: Communications :: Email :: Post-Office :: POP3',
    'Topic :: Internet',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries',
]

# XXX add ref to docs

setup(
    name='leap.mail',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    url='https://leap.se/',
    license='GPLv3+',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    description='Mail Services in the LEAP Client project.',
    long_description=(
        "Mail Services in the LEAP Client project."
    ),
    classifiers=trove_classifiers,
    namespace_packages=["leap"],
    package_dir={'': 'src'},
    packages=find_packages('src'),
    test_suite='leap.mail.load_tests',
    install_requires=utils.parse_requirements(),
    tests_require=utils.parse_requirements(
        reqfiles=['pkg/requirements-testing.pip']),
)
