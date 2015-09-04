# -*- coding: utf-8 -*-
# _decorators.py
# Copyright (C) 2015 LEAP
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
Decorators used in bonafide.
"""


def needs_authentication(func):
    """
    Decorate a method so that it will not be called if the instance
    attribute `is_authenticated` does not evaluate to True.
    """
    def decorated(*args, **kwargs):
        instance = args[0]
        allowed = getattr(instance, 'is_authenticated')
        if not allowed:
            raise RuntimeError('This method requires authentication')
        return func(*args, **kwargs)
    return decorated
