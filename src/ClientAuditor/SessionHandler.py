import logging
from exceptions import StopIteration

logger = logging.getLogger('SessionHandler')

__author__ = 'abb'

class SessionHandler(object):
    '''
    Holds information about the progress and the results of an audit of a single client.
    Created on the very first connection from a client, and handle all subsequent connections from the same client.
    For each connection it fetches a new profile from the profile set and uses it to audit that connection.
    '''

    def __init__(self, session_key, auditor_set):
        self.session_key = session_key
        self.auditor_set_iterator = auditor_set.__iter__()
        self.results = []

    def handle(self, sock):
        # fetching next profile from the profile set
        try:
            auditor = self.auditor_set_iterator.next()
        except StopIteration:
            logger.debug('auditor pool is empty for client %s [key %s]', sock.getpeername(), self.session_key)
            return

        # perform the audit
        res = auditor.handle(sock)
        logger.debug('auditing client %s [key %s] using auditor %s resulted in %s',
            sock.getpeername(), self.session_key, auditor, res)
        self.results.append((auditor, res))