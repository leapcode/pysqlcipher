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


from setuptools import (
    setup,
    find_packages
)


install_requirements = [
    'leap.common',
    'simplejson',
    'requests',
    'python-gnupg',
]


tests_requirements = [
    'mock',
    'leap.soledad.client',
]


setup(
    name='leap.keymanager',
    version='0.3.0',
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
    namespace_packages=["leap"],
    packages=find_packages('src', exclude=['leap.keymanager.tests']),
    package_dir={'': 'src'},
    test_suite='leap.keymanager.tests',
    install_requires=install_requirements,
    tests_require=tests_requirements,
)
