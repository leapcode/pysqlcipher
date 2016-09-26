# Service composition for bitmask-core.
# Run as: twistd -n -y bitmaskd.tac
#
from twisted.application import service
from twisted.python.log import ILogObserver, FileLogObserver

from leap.bitmask.core.service import BitmaskBackend
from leap.bitmask.core.logs import loggerFactory

logger =  loggerFactory()

bb = BitmaskBackend()
application = service.Application("bitmaskd")
application.setComponent(ILogObserver, FileLogObserver(logger).emit)
bb.setServiceParent(application)
