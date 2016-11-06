# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#

import os

from twisted.application import service
from twisted.logger import ILogObserver
from twisted.logger import FileLogObserver
from twisted.logger import FilteringLogObserver
from twisted.logger import LogLevel
from twisted.logger import LogLevelFilterPredicate
from twisted.logger import formatEventAsClassicLogText as formatEvent

from leap.bitmask.core import flags
from leap.bitmask.core.service import BitmaskBackend
from leap.bitmask.core.logs import logFileFactory

bb = BitmaskBackend()
application = service.Application("bitmaskd")

# configure logging
log_file =  logFileFactory()
file_observer = FileLogObserver(log_file, formatEvent)
level = LogLevel.debug if flags.VERBOSE else LogLevel.info
predicate = LogLevelFilterPredicate(defaultLogLevel=level)
observer = FilteringLogObserver(file_observer, [predicate])
application.setComponent(ILogObserver, observer)

bb.setServiceParent(application)
