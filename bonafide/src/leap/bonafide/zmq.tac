# Run as: twistd -n -y zmq.tac
from twisted.application import service
from leap.bonafide.zmq_service import BonafideZMQService
from leap.bonafide.soledad_service import SoledadService

top_service = service.MultiService()
bonafide_zmq_service = BonafideZMQService()
bonafide_zmq_service.setServiceParent(top_service)

# XXX DEBUG -------------------------------------
# This SHOULD BE moved to BITMASK-CORE.
soledad_service = SoledadService()
soledad_service.setName("soledad")
soledad_service.setServiceParent(top_service)
#------------------------------------------------

application = service.Application("bonafide")
top_service.setServiceParent(application)
