# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#
from twisted.application import service
from twisted.logger import ILogObserver
from twisted.logger import FileLogObserver
from twisted.logger import formatEventAsClassicLogText as formatEvent

from leap.bitmask.core.service import BitmaskBackend
from leap.bitmask.core.logs import logFileFactory

bb = BitmaskBackend()
application = service.Application("bitmaskd")

# configure logging
log_file =  logFileFactory()
observer = FileLogObserver(log_file, formatEvent)
application.setComponent(ILogObserver, observer)

bb.setServiceParent(application)
