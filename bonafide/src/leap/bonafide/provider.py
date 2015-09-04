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


class LeapProviderApi(object):
    # TODO when should the provider-api object be created?

    # XXX separate in auth-needing actions?
    # XXX version this mapping !!!

    actions = {
        'signup': ('users', 'POST'),
        'handshake': ('sessions', 'POST'),
        'authenticate': ('sessions/{login}', 'PUT'),
        'update_user': ('users/{uid}', 'PUT'),
        'logout': ('logout', 'DELETE'),
        'get_vpn_cert': ('cert', 'POST'),
        'get_smtp_cert': ('smtp_cert', 'POST'),
    }

    def __init__(self, uri, version):
        self.uri = uri
        self.version = version

    @property
    def base_url(self):
        return "https://{0}/{1}".format(self.uri, self.version)

    # XXX split in two different methods?
    def get_uri_and_method(self, action_name, **extra_params):
        action = self.actions.get(action_name, None)
        if not action:
            raise ValueError("Requested a non-existent action for this API")
        resource, method = action

        uri = '{0}/{1}'.format(bytes(self.base_url), bytes(resource)).format(
            **extra_params)
        return uri, method

    # XXX add a provider_domain property, just to check if it's the right
    # provider domain?
