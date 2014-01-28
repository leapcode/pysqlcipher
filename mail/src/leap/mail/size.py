# -*- coding: utf-8 -*-
# size.py
# Copyright (C) 2014 LEAP
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
Recursively get size of objects.
"""
from gc import collect
from itertools import chain
from sys import getsizeof


def _get_size(item, seen):
    known_types = {dict: lambda d: chain.from_iterable(d.items())}
    default_size = getsizeof(0)

    def size_walk(item):
        if id(item) in seen:
            return 0
        seen.add(id(item))
        s = getsizeof(item, default_size)
        for _type, fun in known_types.iteritems():
            if isinstance(item, _type):
                s += sum(map(size_walk, fun(item)))
                break
        return s

    return size_walk(item)


def get_size(item):
    """
    Return the cumulative size of a given object.

    Currently it supports only dictionaries, and seemingly leaks
    some memory, so use with care.

    :param item: the item which size wants to be computed
    :rtype: int
    """
    seen = set()
    size = _get_size(item, seen)
    del seen
    collect()
    return size
