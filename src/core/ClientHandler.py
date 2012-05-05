''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, itertools
from exceptions import StopIteration
from src.core.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndEvent, ClientAuditResult

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

    Object states:
        right after initialization: next_auditor = None, done = False
        after first and subsequent connection: next_auditor = something, done = False
        after set of auditors is exhausted: next_auditor = None, done = True

    XXX race condition XXX
    '''
    logger = logging.getLogger('ClientHandler')

    def __init__(self, client_id, profiles, res_queue):
        self.client_id = client_id
        self.result = ClientAuditResult(self.client_id)
        self.res_queue = res_queue

        self.nprofiles = try_iterator_length(itertools.chain.from_iterable(profiles))
        self.profiles_iterator = itertools.chain.from_iterable(profiles)
        self.profiles_count = 0

        self.next_profile = None

        self.done = False

    def handle(self, conn):
        '''
        This method is invoked when a new connection arrives.
        '''
        if self.done:
            self.logger.debug('no more profiles for connection %s', conn)
            return

        if self.next_profile == None:
            # this is a very first connection
            try:
                self.next_profile = self.profiles_iterator.next()
                self.profiles_count = self.profiles_count + 1
                self.res_queue.put(ClientAuditStartEvent(self.next_profile, self.client_id))
            except StopIteration:
                self.logger.debug('no profiles for connection %s (the iterator was empty)', conn)
                self.res_queue.put(self.result)
                self.done = True
                return

        # handle this connection
        handler = self.next_profile.get_handler()
        res = handler.handle(conn, self.next_profile)
        self.logger.debug('connection from %s using %s (%d/%d) resulted in %s',
            conn, self.next_profile, self.profiles_count, self.nprofiles, res)

        # log and record the results of the test
        #self.logger.debug('testing client conn %s using %s resulted in %s', conn, self.next_auditor, res)
        self.logger.debug('testing connection %s using %s resulted in %s', conn, self.next_profile, res)
        self.result.add(res)
        self.res_queue.put(res)

        # prefetch next auditor from the iterator, to check if this was the last one
        try:
            self.next_profile = self.profiles_iterator.next()
            self.profiles_count = self.profiles_count + 1
        except StopIteration:
            # it was the last auditor in the set
            self.logger.debug('no more tests for client conn %s', conn)
            self.res_queue.put(ClientAuditEndEvent(self.next_profile, self.client_id))
            self.res_queue.put(self.result)
            self.done = True
