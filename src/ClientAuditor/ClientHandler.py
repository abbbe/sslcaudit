''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
from exceptions import StopIteration
from src.ClientAuditor.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndEvent

class ClientAuditResult(object):
    '''
    This class holds results of invocation of all auditors for one client.
    '''

    def __init__(self, client_id):
        self.client_id = client_id
        self.results = []

    def add(self, res):
        self.results.append(res)


class ClientHandler(object):
    '''
    Instances of this class hold information about the progress and the results of an audit of a single client.
    Normally it gets instantiated on the very first connection from a client and same instance handles all subsequent
    connections from the same client. For each connection it fetches a next auditor object from the auditor set and
    uses it to test that connection. In the process it sends the following events into results queue:
        * ClientAuditStartEvent
    When the set of auditors is exhausted, it pushes XXX.

    Object states:
        right after initialization: next_auditor = None, done = False
        after first and subsequent connection: next_auditor = something, done = False
        after set of auditors is exhausted: next_auditor = None, done = True
    '''
    logger = logging.getLogger('ClientHandler')

    def __init__(self, client_id, auditor_set, res_queue):
        self.client_id = client_id
        self.auditor_set_iterator = auditor_set.__iter__()
        self.result = ClientAuditResult(self.client_id)
        self.res_queue = res_queue

        self.next_auditor = None
        self.auditor_count = 0
        self.done = False

    def handle(self, conn):
        '''
        This method is invoked when a new connection arrives.
        '''
        if self.done:
            self.logger.debug('no more tests for client conn %s', conn)
            return

        if self.next_auditor == None:
            # this is a very first connection
            try:
                self.next_auditor = self.auditor_set_iterator.next()
                self.auditor_count = self.auditor_count + 1
                self.res_queue.put(ClientAuditStartEvent(self.next_auditor, self.client_id))
            except StopIteration:
                self.logger.debug('no tests for client conn %s (iterator was empty)', conn)
                self.res_queue.put(self.result)
                self.done = True
                return

        # audit this client connection
        res = self.next_auditor.handle(conn)

        # log and record the results of the test
        #self.logger.debug('testing client conn %s using %s resulted in %s', conn, self.next_auditor, res)
        self.logger.debug('testing client conn %s using %s resulted in %s', conn, self.next_auditor, res)
        self.result.add(res)
        self.res_queue.put(res)

        # prefetch next auditor from the iterator, to check if this was the last one
        try:
            self.next_auditor = self.auditor_set_iterator.next()
            self.auditor_count = self.auditor_count + 1
        except StopIteration:
            # it was the last auditor in the set
            self.logger.debug('no more tests for client conn %s', conn)
            self.res_queue.put(ClientAuditEndEvent(self.next_auditor, self.client_id))
            self.res_queue.put(self.result)
            self.done = True
