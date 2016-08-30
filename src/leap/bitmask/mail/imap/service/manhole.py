# -*- coding: utf-8 -*-
# manhole.py
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
Utilities for enabling the manhole administrative interface into the
LEAP Mail application.
"""
MANHOLE_PORT = 2222


def getManholeFactory(namespace, user, secret):
    """
    Get an administrative manhole into the application.

    :param namespace: the namespace to show in the manhole
    :type namespace: dict
    :param user: the user to authenticate into the administrative shell.
    :type user: str
    :param secret: pass for this manhole
    :type secret: str
    """
    import string

    from twisted.cred.portal import Portal
    from twisted.conch import manhole, manhole_ssh
    from twisted.conch.insults import insults
    from twisted.cred.checkers import (
        InMemoryUsernamePasswordDatabaseDontUse as MemoryDB)

    from rlcompleter import Completer

    class EnhancedColoredManhole(manhole.ColoredManhole):
        """
        A Manhole with some primitive autocomplete support.
        """
        # TODO use introspection to make life easier

        def find_common(self, l):
            """
            find common parts in thelist items
            ex: 'ab' for ['abcd','abce','abf']
            requires an ordered list
            """
            if len(l) == 1:
                return l[0]

            init = l[0]
            for item in l[1:]:
                for i, (x, y) in enumerate(zip(init, item)):
                    if x != y:
                        init = "".join(init[:i])
                        break

                if not init:
                    return None
            return init

        def handle_TAB(self):
            """
            Trap the TAB keystroke.
            """
            necessarypart = "".join(self.lineBuffer).split(' ')[-1]
            completer = Completer(globals())
            if completer.complete(necessarypart, 0):
                matches = list(set(completer.matches))  # has multiples

                if len(matches) == 1:
                    length = len(necessarypart)
                    self.lineBuffer = self.lineBuffer[:-length]
                    self.lineBuffer.extend(matches[0])
                    self.lineBufferIndex = len(self.lineBuffer)
                else:
                    matches.sort()
                    commons = self.find_common(matches)
                    if commons:
                        length = len(necessarypart)
                        self.lineBuffer = self.lineBuffer[:-length]
                        self.lineBuffer.extend(commons)
                        self.lineBufferIndex = len(self.lineBuffer)

                    self.terminal.nextLine()
                    while matches:
                        matches, part = matches[4:], matches[:4]
                        for item in part:
                            self.terminal.write('%s' % item.ljust(30))
                            self.terminal.write('\n')
                            self.terminal.nextLine()

                self.terminal.eraseLine()
                self.terminal.cursorBackward(self.lineBufferIndex + 5)
                self.terminal.write("%s %s" % (
                    self.ps[self.pn], "".join(self.lineBuffer)))

        def keystrokeReceived(self, keyID, modifier):
            """
            Act upon any keystroke received.
            """
            self.keyHandlers.update({'\b': self.handle_BACKSPACE})
            m = self.keyHandlers.get(keyID)
            if m is not None:
                m()
            elif keyID in string.printable:
                self.characterReceived(keyID, False)

    sshRealm = manhole_ssh.TerminalRealm()

    def chainedProtocolFactory():
        return insults.ServerProtocol(EnhancedColoredManhole, namespace)

    sshRealm = manhole_ssh.TerminalRealm()
    sshRealm.chainedProtocolFactory = chainedProtocolFactory

    portal = Portal(
        sshRealm, [MemoryDB(**{user: secret})])

    f = manhole_ssh.ConchFactory(portal)
    return f
