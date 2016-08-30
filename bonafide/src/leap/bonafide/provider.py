# -*- coding: utf-8 -*-
# provier.py
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
LEAP Provider API.
"""

from copy import deepcopy
import re
from urlparse import urlparse


"""
Maximum API version number supported by bonafide
"""
MAX_API_VERSION = 1


class _MetaActionDispatcher(type):

    """
    A metaclass that will create dispatcher methods dynamically for each
    action made available by the LEAP provider API.

    The new methods will be created according to the values contained in an
    `_actions` dictionary, with the following format::

        {'action_name': (uri_template, method)}

    where `uri_template` is a string that will be formatted with an arbitrary
    number of keyword arguments.

    Any class that uses this one as its metaclass needs to implement two
    private methods::

        _get_uri(self, action_name, **extra_params)
        _get_method(self, action_name)

    Beware that currently they cannot be inherited from bases.
    """

    def __new__(meta, name, bases, dct):

        def _generate_action_funs(dct):
            _get_uri = dct['_get_uri']
            _get_method = dct['_get_method']
            newdct = deepcopy(dct)
            actions = dct['_actions']

            def create_uri_fun(action_name):
                return lambda self, **kw: _get_uri(
                    self, action_name=action_name, **kw)

            def create_met_fun(action_name):
                return lambda self: _get_method(
                    self, action_name=action_name)

            for action in actions:
                uri, method = actions[action]
                _action_uri = 'get_%s_uri' % action
                _action_met = 'get_%s_method' % action
                newdct[_action_uri] = create_uri_fun(action)
                newdct[_action_met] = create_met_fun(action)
            return newdct

        newdct = _generate_action_funs(dct)
        return super(_MetaActionDispatcher, meta).__new__(
            meta, name, bases, newdct)


class BaseProvider(object):

    def __init__(self, netloc, version=1):
        parsed = urlparse(netloc)
        if parsed.scheme != 'https':
            raise ValueError(
                'ProviderApi needs to be passed a url with https scheme')
        self.netloc = parsed.netloc

        self.version = version
        if version > MAX_API_VERSION:
            self.version = MAX_API_VERSION

    def get_hostname(self):
        return urlparse(self._get_base_url()).hostname

    def _get_base_url(self):
        return "https://{0}/{1}".format(self.netloc, self.version)


class Api(BaseProvider):
    """
    An object that has all the information that a client needs to communicate
    with the remote methods exposed by the web API of a LEAP provider.

    The actions are described in https://leap.se/bonafide

    By using the _MetaActionDispatcher as a metaclass, the _actions dict will
    be translated dynamically into a set of instance methods that will allow
    getting the uri and method for each action.

    The keyword arguments specified in the format string will automatically
    raise a KeyError if the needed keyword arguments are not passed to the
    dynamically created methods.
    """

    # TODO when should the provider-api object be created?
    # TODO pass a Provider object to constructor, with autoconf flag.
    # TODO make the actions attribute depend on the api version
    # TODO missing UPDATE USER RECORD

    __metaclass__ = _MetaActionDispatcher
    _actions = {
        'signup': ('users', 'POST'),
        'update_user': ('users/{uid}', 'PUT'),
        'handshake': ('sessions', 'POST'),
        'authenticate': ('sessions/{login}', 'PUT'),
        'logout': ('logout', 'DELETE'),
        'vpn_cert': ('cert', 'POST'),
        'smtp_cert': ('smtp_cert', 'POST'),
    }

    # Methods expected by the dispatcher metaclass

    def _get_uri(self, action_name, **extra_params):
        resource, _ = self._actions.get(action_name)
        uri = '{0}/{1}'.format(
            bytes(self._get_base_url()),
            bytes(resource)).format(**extra_params)
        return uri

    def _get_method(self, action_name):
        _, method = self._actions.get(action_name)
        return method


class Discovery(BaseProvider):
    """
    Discover basic information about a provider, including the provided
    services.
    """

    __metaclass__ = _MetaActionDispatcher
    _actions = {
        'provider_info': ('provider.json', 'GET'),
        'configs': ('1/configs.json', 'GET'),
    }

    def _get_base_url(self):
        return "https://{0}".format(self.netloc)

    def get_base_uri(self):
        return self._get_base_url()

    # Methods expected by the dispatcher metaclass

    def _get_uri(self, action_name, **extra_params):
        resource, _ = self._actions.get(action_name)
        uri = '{0}/{1}'.format(
            bytes(self._get_base_url()),
            bytes(resource)).format(**extra_params)
        return uri

    def _get_method(self, action_name):
        _, method = self._actions.get(action_name)
        return method


def validate_username(username):
    accepted_characters = '^[a-z0-9\-\_\.]*$'
    if not re.match(accepted_characters, username):
        raise ValueError('Only lowercase letters, digits, . - and _ allowed.')
