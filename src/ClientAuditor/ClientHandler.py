import logging
from exceptions import StopIteration
from src.ClientAuditor.ClientConnectionAuditResult import ClientConnectionAuditResultStart, ClientConnectionAuditResultEnd

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
    Holds information about the progress and the results of an audit of a single client. Gets created on the very first
    connection from a client, and handles all subsequent connections from the same client.
    For each connection it fetches a new auditor object from the set and uses it to test that connection.
    When the set of auditors is exhausted, it pushes
    '''
    logger = logging.getLogger('ClientHandler')

    def __init__(self, client_id, auditor_set, res_queue):
        self.client_id = client_id
        self.auditor_set_iterator = auditor_set.__iter__()
        self.result = ClientAuditResult(self.client_id)
        self.res_queue = res_queue
        self.closed = False

        self.res_queue.put(ClientConnectionAuditResultStart(client_id))

    def handle(self, conn):
        '''
        This method is invoked when a new connection arrives.
        '''
        if self.closed:
            self.logger.debug('no more tests for client conn %s', conn)
            return

        # fetching next profile from the profile set
        try:
            auditor = self.auditor_set_iterator.next()
        except StopIteration:
            self.logger.debug('no more tests for client conn %s', conn)
            self.close()
            return

        # test this client connection
        res = auditor.handle(conn)

        # log and record the results of the test
        self.logger.debug('testing client conn %s using %s resulted in %s', conn, auditor, res)
        self.result.add(res)
        self.res_queue.put(res)

    def close(self):
        '''
        This method is invoked when there are no more auditors left in the set.
        This method is expected to deliver the result set back to the user of this class.
        '''
        if not self.closed:
            self.res_queue.put(ClientConnectionAuditResultEnd(self.client_id))
            self.res_queue.put(self.result)
            self.closed = True
