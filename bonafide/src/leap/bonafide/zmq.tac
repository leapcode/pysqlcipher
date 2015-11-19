# Run as: twistd -n -y zmq.tac
from twisted.application import service
from leap.bonafide.zmq_service import BonafideZMQService

top_service = service.MultiService()
bonafide_zmq_service = BonafideZMQService()
bonafide_zmq_service.setServiceParent(top_service)

application = service.Application("bonafide")
top_service.setServiceParent(application)
