import logging
from SocketServer import BaseRequestHandler
from src.ClientAuditor.SessionHandler import SessionHandler

logger = logging.getLogger('ConnectionHandler')

class ConnectionHandler(BaseRequestHandler):
    '''
    Incoming connection handler. Based on a session key for a given connection, passes the request
    to an appropriate session handler. Create new session handler if not exists yet.
    '''

    def handle(self):
        # identify session key
        session_key = self.server.get_session_key(self.request)
        # find or create a session handler
        if not self.server.sessions.has_key(session_key):
            logger.debug("new client %s [key %s]", self.request.getpeername(), session_key)
            self.server.sessions[session_key] = SessionHandler(session_key, self.server.auditor_set)
            # pass the request to the session handler
        self.server.sessions[session_key].handle(self.request)