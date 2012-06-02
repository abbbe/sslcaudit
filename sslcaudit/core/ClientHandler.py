# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, threading
from exceptions import StopIteration
from sslcaudit.core.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndResult

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
        self.lock = threading.Lock()  # this lock has to be acquired before using nused_profiles and result attributes

        self.res_queue.put(ClientAuditStartEvent(self.client_id, self.profiles))

    def handle(self, conn):
        '''
        This method is invoked when a new connection arrives. Can be invoked more then once in parallel,
        from different threads. It takes the next unused profile from the list (in a thread-safe way),
        uses it to handle this connection, and submits the result of handling this specific connection
        to the results queue. It detects when the very last handler quits and issues audit-end-res event.
        '''

        # get the index of the profile to use to handle this connection
        with self.lock:
            if self.nused_profiles < len(self.profiles):
                profile_index = self.nused_profiles
                self.nused_profiles += 1
            else:
                profile_index = -1

        if profile_index != -1:
            # handle this connection with this profile
            self.logger.debug('will use profile %d to handle connection %s', profile_index, conn)
            profile = self.profiles[profile_index]
            handler = profile.get_handler()
            res = handler.handle(conn, profile)

            # log and record the results of the test
            self.logger.debug('handling connection %s using %s (%d/%d) resulted in %s',
                conn, profile, profile_index, len(self.profiles), res)
            self.res_queue.put(res)

            # see if this thread is the very last handler out there
            with self.lock:
                self.result.add(res)
                if len(self.result.results) >= len(self.profiles):
                    # the result object seems to contains enough results, this must be the very last handler out there
                    # submit the final result to the queue
                    self.logger.debug('last profile for connection %s', conn)
                    self.res_queue.put(self.result)

        else:
            # no more profiles to apply, resort to the posttest handler
            self.logger.debug('no unused profiles for connection %s, invoking the posttest handler', conn)
            self.handle_posttest_connection(conn)

    def handle_posttest_connection(self, conn):
        pass
