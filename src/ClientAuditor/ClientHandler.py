import logging
from exceptions import StopIteration
from papyon.gnet.io import sock
from src.ClientAuditor.ClientAuditor import ClientAuditResult, ClientAuditResultStart, ClientAuditResultEnd

logger = logging.getLogger('SessionHandler')

class SessionResult(object):
    '''
    This class holds results of invocation of all auditors for one client.
    '''

    def __init__(self, session_key):
        self.session_key = session_key
        self.results = []

    def add(self, res):
        self.results.append(res)


class ClientHandler(object):
    '''
    Holds information about the progress and the results of an audit of a single client.
    Gets created on the very first connection from a client, and handles all subsequent connections from the same client.
    For each connection it fetches a new auditor object from the set and uses it to test that connection.
    When the set of auditors is exhausted, it pushes
    '''

    def __init__(self, session_key, auditor_set, res_queue):
        self.client_id = session_key
        self.auditor_set_iterator = auditor_set.__iter__()
        self.session_result = SessionResult(self.client_id)
        self.res_queue = res_queue
        self.closed = False

        self.res_queue.put(ClientAuditResultStart(session_key))

    def handle(self, conn):
        if self.closed:
            logger.debug('session is closed for client %s [key %s]', conn.getpeername(), conn.get_client_id())
            return

        # fetching next profile from the profile set
        try:
            auditor = self.auditor_set_iterator.next()
        except StopIteration:
            logger.debug('auditor pool is empty for client %s [key %s]', conn.getpeername(), conn.get_client_id())
            self.close()
            return

        # perform the audit
        res = auditor.handle(sock)
        logger.debug('auditing client %s [key %s] using auditor %s resulted in %s',
            conn.getpeername(), conn.get_client_id(), auditor, res)
        self.res_queue.put(res)

    def close(self):
        '''
        This method is invoked when there are no more auditors left in the set.
        This method is expected to deliver the result set back to the user of this class.
        '''
        if not self.closed:
            self.res_queue.put(ClientAuditResultEnd(self.client_id))
            self.closed = True
