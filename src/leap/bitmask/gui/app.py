# -*- coding: utf-8 -*-
# app.py
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
Main entrypoint for the Bitmask Qt GUI.
It just launches a wekbit browser that runs the local web-ui served by bitmaskd
when the web service is running.
"""

import sys

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import QtWebKit, QtWebKitWidgets

from bitmask.core.launcher import run_bitmaskd()

BITMASK_URI = 'http://localhost:7070'

qApp = None


class BrowserWindow(QtWidgets.QDialog):

    def __init__(self, parent):
        super(BrowserWindow, self).__init__(parent)
        self.view = QtWebKitWidgets.QWebView(self)
        self.setWindowTitle('Bitmask')
        self.resize(800, 600)
        self.load_app()

    def load_app(self):
        self.view.load(QtCore.QUrl(BITMASK_URI))

    def shutdown(self):
        print('[bitmask] shutting down...')
        try:
            self.view.stop()
            QtCore.QTimer.singleShot(0, qApp.deleteLater)

        except Exception as ex:
            print('exception catched: %r' % ex)
            sys.exit(1)


def start_app():

    global qApp

    # TODO should do it if no pid
    run_bitmaskd()

    qApp = QtWidgets.QApplication([])
    browser = BrowserWindow(None)

    qApp.setQuitOnLastWindowClosed(True)
    qApp.lastWindowClosed.connect(browser.shutdown)

    browser.show()
    sys.exit(qApp.exec_())


if __name__ == "__main__":
    start_app()
