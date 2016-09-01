APPNAME = "bitmask.core"
ENDPOINT = "ipc:///tmp/%s.sock" % APPNAME

# FIXME some temporary imports to make the modules
# appear in the coverage report. Remove the imports when
# test code cover them.
import service
import uuid_map
import mail_services
import dispatcher
