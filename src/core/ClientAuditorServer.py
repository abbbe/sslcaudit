''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import  logging
from SocketServer import TCPServer
from threading import Thread
from Queue import Queue
from src.core.ClientConnection import ClientConnection
from src.core.ClientHandler import ClientHandler

logger = logging.getLogger('ClientAuditorTCPServer')

#class ClientAuditorTCPServer(ThreadingMixIn, TCPServer):
class ClientAuditorTCPServer(TCPServer):
    '''
    This class extends TCPServer to enforce address reuse, enforce daemon threads, and allow threading.
    '''

    def __init__(self, listen_on):
        TCPServer.__init__(self, listen_on, None, bind_and_activate=False)
        self.daemon_threads = True
        self.allow_reuse_address = True

        try:
            self.server_bind()
        except Exception as ex:
            raise Exception('Caught exception while binding to %s: %s' % (listen_on, ex))

        self.server_activate()


class ClientAuditorServer(Thread):
    '''
    This class extends TCP server to handle incoming connection from clients under test. Each
    client is expected to establish a number of connections to the server.

    The server distinguishes between connections from different clients by source IP address.
    All connections from the same source IP address are considered to correspond to the same
    client.
    '''

    def __init__(self, listen_on, auditor_sets, res_queue=None):
        Thread.__init__(self, target=self.run)
        self.daemon = True

        self.listen_on = listen_on
        self.clients = {}
        self.auditor_sets = auditor_sets

        if res_queue == None:
            self.res_queue = Queue()
        else:
            self.res_queue = res_queue

        # create TCP listener with SO_REUSE_ADDR socket option
        self.tcp_server = ClientAuditorTCPServer(self.listen_on)
        self.tcp_server.finish_request = self.finish_request

    def finish_request(self, sock, client_address):
        # this method overrides TCPServer implementation and actually handles new connections
        # create new conn object and obtain client id
        conn = ClientConnection(sock, client_address)
        client_id = conn.get_client_id()

        # find or create a session handler
        if not self.clients.has_key(client_id):
            logger.debug('new client %s [id %s]', conn, client_id)
            self.clients[client_id] = ClientHandler(client_id, self.auditor_sets, self.res_queue)
            # pass the request to the client handler

        # handle the request
        self.clients[client_id].handle(conn)

    def run(self):
        logger.debug('running %s, listen_on %s, auditor_set %s', self, self.listen_on, self.auditor_sets)
        self.tcp_server.serve_forever()

