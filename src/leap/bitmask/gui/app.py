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
import platform
import signal
import sys

from functools import partial
from multiprocessing import Process

from leap.bitmask.core.launcher import run_bitmaskd, pid

from leap.bitmask.gui import app_rc


if platform.system() == 'Windows':
    from multiprocessing import freeze_support
    from PySide import QtCore, QtGui
    from PySide import QtWebKit
    from PySide.QtGui import QDialog
    from PySide.QtGui import QApplication
    from PySide.QtWebKit import QWebView, QGraphicsWebView
    from PySide.QtCore import QSize
else:
    from PyQt5 import QtCore, QtGui
    from PyQt5 import QtWebKit
    from PyQt5.QtWidgets import QDialog
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtWebKitWidgets import QWebView
    from PyQt5.QtCore import QSize


BITMASK_URI = 'http://localhost:7070'

IS_WIN = platform.system() == "Windows"
DEBUG = os.environ.get("DEBUG", False)

qApp = None
bitmaskd = None


class BrowserWindow(QDialog):

    def __init__(self, parent):
        super(BrowserWindow, self).__init__(parent)
        if IS_WIN:
            self.view = QWebView(self)
            win_size = QSize(1024, 600)
            self.setMinimumSize(win_size)
            self.view.page().setViewportSize(win_size)
            self.view.page().setPreferredContentsSize(win_size)
        else:
            self.view = QWebView(self)
            win_size = QSize(800, 600)
        self.win_size = win_size
        self.resize(win_size)

        if DEBUG:
            self.view.settings().setAttribute(
                QtWebKit.QWebSettings.WebAttribute.DeveloperExtrasEnabled,
                True)
            self.inspector = QtWebKit.QWebInspector(self)
            self.inspector.setPage(self.view.page())
            self.inspector.show()
            self.splitter = QtGui.QSplitter()
            self.splitter.addWidget(self.view)
            self.splitter.addWidget(self.inspector)
            # TODO add layout also in non-DEBUG mode
            layout = QtGui.QVBoxLayout(self)
            layout.addWidget(self.splitter)

        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/mask-icon.png"),
                       QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)

        self.setWindowTitle('Bitmask')
        self.load_app()
        self.closing = False

    def load_app(self):
        self.view.load(QtCore.QUrl(BITMASK_URI))

    def shutdown(self, *args):
        if self.closing:
            return
        self.closing = True
        global bitmaskd
        bitmaskd.join()
        if os.path.isfile(pid):
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


def _handle_kill(*args, **kw):
    win = kw.get('win')
    if win:
        QtCore.QTimer.singleShot(0, win.close)


def launch_gui():
    global qApp
    global bitmaskd

    if IS_WIN:
        freeze_support()
    bitmaskd = Process(target=run_bitmaskd)
    bitmaskd.start()

    qApp = QApplication([])
    browser = BrowserWindow(None)

    qApp.setQuitOnLastWindowClosed(True)
    qApp.lastWindowClosed.connect(browser.shutdown)

    signal.signal(
        signal.SIGINT,
        partial(_handle_kill, win=browser))

    # Avoid code to get stuck inside c++ loop, returning control
    # to python land.
    timer = QtCore.QTimer()
    timer.timeout.connect(lambda: None)
    timer.start(500)

    browser.show()
    sys.exit(qApp.exec_())


def start_app():
    from leap.bitmask.util import STANDALONE

    # Allow the frozen binary in the bundle double as the cli entrypoint
    # Why have only a user interface when you can have two?

    if platform.system() == 'Windows':
        # In windows, there are some args added to the invocation
        # by PyInstaller, I guess...
        MIN_ARGS = 3
    else:
        MIN_ARGS = 1

    # DEBUG ====================================
    if STANDALONE and len(sys.argv) > MIN_ARGS:
        from leap.bitmask.cli import bitmask_cli
        return bitmask_cli.main()
    launch_gui()


if __name__ == "__main__":
    start_app()
