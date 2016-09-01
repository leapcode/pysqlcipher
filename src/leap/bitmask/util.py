# -*- coding: utf-8 -*-
# util.py
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
Handy common utils
"""
import os
import sys


def here(module=None):
    if getattr(sys, 'frozen', False):
        # we are running in a |PyInstaller| bundle
        return sys._MEIPASS
    else:
        dirname = os.path.dirname
        if module:
            return dirname(module.__file__)
        else:
            return dirname(__file__)
