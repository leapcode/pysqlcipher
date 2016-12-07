import json
from twisted.web.server import NOT_DONE_YET

from twisted.web.resource import Resource


class Api(Resource):

    isLeaf = True

    def __init__(self, dispatcher):
        Resource.__init__(self)
        self.dispatcher = dispatcher

    def render_POST(self, request):
        command = request.uri.split('/')[2:]
        params = request.content.getvalue()
        if params:
            # json.loads returns unicode strings and the rest of the code
            # expects strings. This 'str(param)' conversion can be removed
            # if we move to python3
            for param in json.loads(params):
                command.append(str(param))

        d = self.dispatcher.dispatch(command)
        d.addCallback(self._write_response, request)
        return NOT_DONE_YET

    def _write_response(self, response, request):
        request.setHeader('Content-Type', 'application/json')
        request.write(response)
        request.finish()
