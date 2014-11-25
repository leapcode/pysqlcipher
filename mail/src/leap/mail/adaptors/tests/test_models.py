# -*- coding: utf-8 -*-
# test_models.py
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
Tests for the leap.mail.adaptors.models module.
"""
from twisted.trial import unittest

from leap.mail.adaptors import models


class SerializableModelsTestCase(unittest.TestCase):

    def test_good_serialized_model(self):

        class M(models.SerializableModel):
            foo = 42
            bar = 33
            baaz_ = None
            _nope = 0
            __nope = 0

            def not_today(self):
                pass

            class IgnoreMe(object):
                pass

            killmeplease = lambda x: x

        serialized = M.serialize()
        expected = {'foo': 42, 'bar': 33, 'baaz': None}
        self.assertEqual(serialized, expected)


class DocumentWrapperTestCase(unittest.TestCase):

    def test_wrapper_defaults(self):

        class Wrapper(models.DocumentWrapper):
            class model(models.SerializableModel):
                foo = 42
                bar = 11

        wrapper = Wrapper()
        wrapper._ignored = True
        serialized = wrapper.serialize()
        expected = {'foo': 42, 'bar': 11}
        self.assertEqual(serialized, expected)

    def test_initialized_wrapper(self):

        class Wrapper(models.DocumentWrapper):
            class model(models.SerializableModel):
                foo = 42
                bar_ = 11

        wrapper = Wrapper(foo=0, bar=-1)
        serialized = wrapper.serialize()
        expected = {'foo': 0, 'bar': -1}
        self.assertEqual(serialized, expected)

        wrapper.foo = 23
        serialized = wrapper.serialize()
        expected = {'foo': 23, 'bar': -1}
        self.assertEqual(serialized, expected)

        wrapper = Wrapper(foo=0)
        serialized = wrapper.serialize()
        expected = {'foo': 0, 'bar': 11}
        self.assertEqual(serialized, expected)

    def test_invalid_initialized_wrapper(self):

        class Wrapper(models.DocumentWrapper):
            class model(models.SerializableModel):
                foo = 42
        getwrapper = lambda: Wrapper(bar=1)
        self.assertRaises(RuntimeError, getwrapper)

    def test_no_model_wrapper(self):

        class Wrapper(models.DocumentWrapper):
            pass

        def getwrapper():
            w = Wrapper()
            w.foo = None

        self.assertRaises(RuntimeError, getwrapper)
