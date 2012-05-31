''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, itertools
from exceptions import StopIteration
from sslcaudit.core.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndResult

def try_iterator_length(iter):
    '''
    Tries to traverse the iterator and returns sequence length
    '''
    length = 0
    while True:
        try:
            iter.next()
            length += 1
        except StopIteration:
            return length

class ClientHandler(object):
    '''
    Instances of this class hold information about the progress and the results of an audit of a single client.
    Normally it gets instantiated on the very first connection from a client and same instance handles all subsequent
    connections from the same client. For each connection it fetches a next auditor object from the predefined
    auditor set and uses that auditor to test the connection. It sends ClientAuditStartEvent event on first client
    connection. After each connection is handled, it pushes the result returned by the auditor, which normally is
    ClientConnectionAuditResult or another subclass of ClientConnectionAuditEvent. After the last auditor has
    finished its work it pushes ClientAuditEndEvent and ClientAuditResult into the queue.
    '''
    logger = logging.getLogger('ClientHandler')

    def __init__(self, client_id, profiles, res_queue):
        self.client_id = client_id
        self.result = ClientAuditEndResult(self.client_id)
        self.res_queue = res_queue

        self.profiles = profiles
        self.nused_profiles = 0

        self.res_queue.put(ClientAuditStartEvent(self.client_id, self.profiles))

    def handle(self, conn):
        '''
        This method is invoked when a new connection arrives. Can be invoked more then once in parallel,
        from different threads.
        '''
        if self.nused_profiles >= len(self.profiles):
                self.logger.debug('no more profiles for connection %s', conn)
                if self.result:
                    self.res_queue.put(self.result)
                    self.result = None
                return

        # handle this connection
        profile = self.profiles[self.nused_profiles]
        handler = profile.get_handler()
        res = handler.handle(conn, profile)

        # log and record the results of the test
        self.logger.debug('connection from %s using %s (%d/%d) resulted in %s',
            conn, profile, self.nused_profiles, len(self.profiles), res)
        self.result.add(res)
        self.res_queue.put(res)

        # if this was the last profile for this client
        self.nused_profiles = self.nused_profiles + 1
        if self.nused_profiles >= len(self.profiles):
            # it was the last profile for this client
            self.logger.debug('last profile for connection %s', conn)
            self.res_queue.put(self.result)
