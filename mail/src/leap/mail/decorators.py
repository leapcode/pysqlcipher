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

from functools import wraps

from twisted.internet.threads import deferToThread


logger = logging.getLogger(__name__)


# TODO
# Should write a helper to be able to pass a timeout argument.
# See this answer: http://stackoverflow.com/a/19019648/1157664
# And the notes by glyph and jpcalderone

def deferred_to_thread(f):
    """
    Decorator, for deferring methods to Threads.

    It will do a deferToThread of the decorated method
    unless the environment variable LEAPMAIL_DEBUG is set.

    It uses a descriptor to delay the definition of the
    method wrapper.
    """
    class descript(object):
        """
        The class to be used as decorator.

        It takes any method as the passed object.
        """

        def __init__(self, f):
            """
            Initializes the decorator object.

            :param f: the decorated function
            :type f: callable
            """
            self.f = f

        def __get__(self, instance, klass):
            """
            Descriptor implementation.

            At creation time, the decorated `method` is unbound.

            It will dispatch the make_unbound method if we still do not
            have an instance available, and the make_bound method when the
            method has already been bound to the instance.

            :param instance: the instance of the class, or None if not exist.
            :type instance: instantiated class or None.
            """
            if instance is None:
                # Class method was requested
                return self.make_unbound(klass)
            return self.make_bound(instance)

        def _errback(self, failure):
            """
            Errorback that logs the exception catched.

            :param failure: a twisted failure
            :type failure: Failure
            """
            logger.warning('Error in method: %s' % (self.f.__name__))
            logger.exception(failure.getTraceback())

        def make_unbound(self, klass):
            """
            Return a wrapped function with the unbound call, during the
            early access to the decortad method. This gets passed
            only the class (not the instance since it does not yet exist).

            :param klass: the class to which the still unbound method belongs
            :type klass: type
            """

            @wraps(self.f)
            def wrapper(*args, **kwargs):
                """
                We're temporarily wrapping the decorated method, but this
                should not be called, since our application should use
                the bound-wrapped method after this decorator class has been
                used.

                This documentation will vanish at runtime.
                """
                raise TypeError(
                    'unbound method {}() must be called with {} instance '
                    'as first argument (got nothing instead)'.format(
                        self.f.__name__,
                        klass.__name__)
                )
            return wrapper

        def make_bound(self, instance):
            """
            Return a function that wraps the bound method call,
            after we are able to access the instance object.

            :param instance: an instance of the class the decorated method,
                             now bound, belongs to.
            :type instance: object
            """

            @wraps(self.f)
            def wrapper(*args, **kwargs):
                """
                Do a proper function wrapper that defers the decorated method
                call to a separated thread if the LEAPMAIL_DEBUG
                environment variable is set.

                This documentation will vanish at runtime.
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
