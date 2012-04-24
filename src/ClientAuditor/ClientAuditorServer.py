import logging
from SocketServer import TCPServer, ThreadingMixIn
from threading import Thread
from Queue import Queue
from src.ClientAuditor.ClientConnection import ClientConnection
from src.ClientAuditor.ClientHandler import ClientHandler

logger = logging.getLogger('ClientAuditorServer')

class ClientAuditorServer(ThreadingMixIn, TCPServer, Thread):
    '''
    This class extends TCP server to handle incoming connection from clients under test. Each
    client is expected to establish a number of connections to the server.

    The server distinguishes between connections from different clients by source IP address.
    All connections from the same source IP address are considered to correspond to the same
    client.
    '''

    def __init__(self, listen_on, auditor_set, res_queue=None):
        # create TCP listener with SO_REUSE_ADDR socket option
        TCPServer.__init__(self, listen_on, None, bind_and_activate=False)
        self.daemon_threads = True
        self.allow_reuse_address = True
        self.server_bind()
        self.server_activate()

        # make the listener itself run in the separate thread
        Thread.__init__(self, target=self.run)
        self.daemon = True

        self.listen_on = listen_on
        self.clients = {}
        self.auditor_set = auditor_set

        if res_queue == None:
            self.res_queue = Queue()
        else:
            self.res_queue = res_queue


    def finish_request(self, sock, client_address):
        # this method overrides TCPServer implementation and actually handles new connections
        # create new conn object and obtain client id
        conn = ClientConnection(sock, client_address)
        client_id = conn.get_client_id()

        # find or create a session handler
        if not self.clients.has_key(client_id):
            logger.debug('new client %s [id %s]', conn, client_id)
            self.clients[client_id] = ClientHandler(client_id, self.auditor_set, self.res_queue)
            # pass the request to the client handler
        self.clients[client_id].handle(conn)


    def run(self):
        logger.debug('running %s, listen_on %s, auditor_set %s', self, self.listen_on, self.auditor_set)
        while True:
            self.handle_request()

