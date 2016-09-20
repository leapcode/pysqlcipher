# -*- coding: utf-8 -*-
# webui.py
# Copyright (C) 2016 LEAP Encryption Access Project
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
Bitmask Command Line interface: webui
"""

from leap.bitmask.cli import command


class WebUI(command.Command):
    service = 'webui'
    usage = '''{name} webui <subcommand>

Bitmask Web User Interface

SUBCOMMANDS:

   enable               Start service
   disable              Stop service
   status               Display status about service

'''.format(name=command.appname)

    commands = ['enable', 'disable', 'status']
