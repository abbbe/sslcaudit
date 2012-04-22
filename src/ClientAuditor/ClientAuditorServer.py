import logging
from SocketServer import TCPServer
from src.ClientAuditor.ConnectionHandler import ConnectionHandler

logger = logging.getLogger('ClientAuditorServer')

class ClientAuditorServer(TCPServer):
    '''
    This class extends TCP server to handle incoming connection from clients under test. Each
    client is expected to establish a number of connections to the server.

    The server distinguishes between connections from different clients by source IP address.
    All connections from the same source IP address are considered to correspond to the same
    client (defined by implementation of get_session_key() method).
    '''

    def __init__(self, listen_on, auditor_set):
        # create TCP listener with SO_REUSE_ADDR socket option
        TCPServer.__init__(self, listen_on, ConnectionHandler, bind_and_activate=False)
        self.allow_reuse_address = True
        self.server_bind()
        self.server_activate()

        self.listen_on = listen_on
        self.sessions = {}
        self.auditor_set = auditor_set

    def get_session_key(self, sock):
        '''
        This function returns a session key for a given socket. A key is used to distinguish
        between different clients under test. In the current implementation we use client IP
        address as a key.
        '''
        return sock.getpeername()[0]

    def run(self):
        logger.debug("starting %s on %s using %s", self.__class__.__name__, self.listen_on, self.auditor_set)
        while True:
            self.handle_request()