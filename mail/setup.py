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


from setuptools import setup, find_packages


requirements = [
    "leap.soledad",
    "leap.common>=0.2.3-dev",
    "leap.keymanager>=0.2.0",
    "twisted",
]

tests_requirements = [
    'setuptools-trial',
    'mock',
]

# XXX add classifiers, docs
setup(
    name='leap.mail',
    version='0.2.0-dev',
    url='https://leap.se/',
    license='GPLv3+',
    author='The LEAP Encryption Access Project',
    author_email='info@leap.se',
    description='Mail Services in the LEAP Client project.',
    long_description=(
        "Mail Services in the LEAP Client project."
    ),
    namespace_packages=["leap"],
    package_dir={'': 'src'},
    packages=find_packages('src'),
    test_suite='leap.mail.load_tests',
    install_requires=requirements,
    tests_require=tests_requirements,
)
