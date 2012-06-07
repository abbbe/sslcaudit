# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import  logging
from threading import Thread
from Queue import Queue
import itertools
import threading
from sslcaudit.core.ClientConnection import ClientConnection
from sslcaudit.core.ClientServerSessionHandler import ClientServerSessionHandler
from sslcaudit.core.ThreadingTCPServer import ThreadingTCPServer
from sslcaudit.core.get_original_dst import get_original_dst

logger = logging.getLogger('ClientAuditorTCPServer')


class ClientAuditorServer(Thread):
    '''
    This class is instantiated with a specification of listen port, a list of profile factories, and a result queue.
    It works in a separate Thread and relies on ClientAuditorTCPServer server to actually receive TCP connections from
    clients and invoke finish_request() method (weird name, but it is the way the stock TCP python server works).
    It distinguishes between different clients by their IP addresses, ignoring TCP port.
    It distinguishes between different servers (may be more than one if redirection takes place) by address/port pairs.
    It creates an instance of ClientServerSessionHandler class for each distinct client-server pair and calls its
    handle() for each incoming connection relevant to that session.
    Right now this generates the list of profiles by flattening 'profile_factories' and passes the result to the
    constructor of ClientServerSessionHandler. This will change.
    If res_queue is None, this class will create its own Queue and make accessible to users via res_queue attribute.
    '''

    def __init__(self, listen_on, profile_factories, res_queue=None):
        Thread.__init__(self, target=self.run, name='ClientAuditorServer')
        self.daemon = True

        self.listen_on = listen_on
        self.client_server_sessions = {}
        self.lock = threading.Lock()  # this lock has to be acquired before using clients dictionary
        self.profile_factories = profile_factories

        # create a local result queue unless one is already provided
        if res_queue == None:
            self.res_queue = Queue()
        else:
            self.res_queue = res_queue

        # create TCP server and make it use our method to handle the requests
        self.tcp_server = ThreadingTCPServer(self.listen_on)
        self.tcp_server.finish_request = self.finish_request

    def finish_request(self, sock, client_address):
        # this method overrides TCPServer implementation and actually handles new connections
        # it may be invoked from different threads, in parallel

        try:
            orig_dst = get_original_dst(sock)
            print '*** ORIG_DEST >%s<' % orig_dst
        except Exception as ex:
            print 'get_original_dst() has thrown an exception: %s' % ex

        # create new conn object and obtain client id
        conn = ClientConnection(sock, client_address)
        session_id = conn.get_session_id()

        # find or create a session handler
        with self.lock:
            if not self.client_server_sessions.has_key(session_id):
                logger.debug('new session [id %s]', session_id)
                profiles = self.mk_session_profiles()
                handler = ClientServerSessionHandler(session_id, profiles, self.res_queue)
                self.client_server_sessions[session_id] = handler
            else:
                handler = self.client_server_sessions[session_id]

        # handle the request
        handler.handle(conn)

    def run(self):
        logger.info('listen_on: %s' % str(self.listen_on))
        self.tcp_server.serve_forever()

    def stop(self):
        ''' this method can only be invoked if the server is already running '''
        self.tcp_server.shutdown()
        self.server_close()

    def server_close(self):
        self.tcp_server.server_close()

    def mk_session_profiles(self):
        return list(itertools.chain.from_iterable(self.profile_factories))
