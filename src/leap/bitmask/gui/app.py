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

import os
import signal
import sys

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import QtWebKit, QtWebKitWidgets

from leap.bitmask.core.launcher import run_bitmaskd, pid

from multiprocessing import Process


BITMASK_URI = 'http://localhost:7070'

qApp = None
bitmaskd = None


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
        global bitmaskd
        bitmaskd.join()
        with open(pid) as f:
            pidno = int(f.read())
        print('[bitmask] terminating bitmaskd...')
        os.kill(pidno, signal.SIGTERM)
        print('[bitmask] shutting down gui...')
        try:
            self.view.stop()
            QtCore.QTimer.singleShot(0, qApp.deleteLater)

        except Exception as ex:
            print('exception catched: %r' % ex)
            sys.exit(1)


def launch_gui():
    global qApp
    global bitmaskd

    bitmaskd = Process(target=run_bitmaskd)
    bitmaskd.start()

    qApp = QtWidgets.QApplication([])
    browser = BrowserWindow(None)

    qApp.setQuitOnLastWindowClosed(True)
    qApp.lastWindowClosed.connect(browser.shutdown)

    browser.show()
    sys.exit(qApp.exec_())


def start_app():
    from leap.bitmask.util import STANDALONE

    # Allow the frozen binary in the bundle double as the cli entrypoint
    # Why have only a user interface when you can have two?

    if STANDALONE and len(sys.argv) > 1:
        from leap.bitmask.cli import bitmask_cli
        return bitmask_cli.main()

    launch_gui()


if __name__ == "__main__":
    start_app()
