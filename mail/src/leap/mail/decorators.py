# -*- coding: utf-8 -*-
# decorators.py
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
Useful decorators for mail package.
"""
import logging
import os
import sys
import traceback

from functools import wraps

from twisted.internet.threads import deferToThread
from twisted.python import log

logger = logging.getLogger(__name__)


def deferred(f):
    """
    Decorator, for deferring methods to Threads.

    It will do a deferToThread of the decorated method
    unless the environment variable LEAPMAIL_DEBUG is set.

    It uses a descriptor to delay the definition of the
    method wrapper.
    """
    class descript(object):
        def __init__(self, f):
            self.f = f

        def __get__(self, instance, klass):
            if instance is None:
                # Class method was requested
                return self.make_unbound(klass)
            return self.make_bound(instance)

        def _errback(self, failure):
            err = failure.value
            logger.warning('error in method: %s' % (self.f.__name__))
            logger.exception(err)
            log.err(err)

        def make_unbound(self, klass):

            @wraps(self.f)
            def wrapper(*args, **kwargs):
                """
                this doc will vanish
                """
                raise TypeError(
                    'unbound method {}() must be called with {} instance '
                    'as first argument (got nothing instead)'.format(
                        self.f.__name__,
                        klass.__name__)
                )
            return wrapper

        def make_bound(self, instance):

            @wraps(self.f)
            def wrapper(*args, **kwargs):
                """
                This documentation will disapear
                """
                if not os.environ.get('LEAPMAIL_DEBUG'):
                    d = deferToThread(self.f, instance, *args, **kwargs)
                    d.addErrback(self._errback)
                    return d
                else:
                    return self.f(instance, *args, **kwargs)

            # This instance does not need the descriptor anymore,
            # let it find the wrapper directly next time:
            setattr(instance, self.f.__name__, wrapper)
            return wrapper

    return descript(f)
