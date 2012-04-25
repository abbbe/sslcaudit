import logging
import src

logging.basicConfig()

import unittest

from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.ClientAuditor.ClientConnectionAuditEvent import ClientAuditEndEvent, ClientAuditStartEvent, ClientConnectionAuditResult, PositiveAuditResult, NegativeAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.Main import Main, SSLCERT_MODULE_NAME, DUMMY_MODULE_NAME

from src.Test.SSLHammer import NotVerifyingSSLHammer, VerifyingSSLHammer
from src.Test.TCPHammer import TCPHammer

TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_BASEPORT = 10000

def get_next_listener_port():
    '''
    This method used to allocate ports the test server will listen on
    '''
    global TEST_LISTENER_BASEPORT
    TEST_LISTENER_BASEPORT = TEST_LISTENER_BASEPORT + 1
    return TEST_LISTENER_BASEPORT


class TestMain(unittest.TestCase):
    '''
    This tests Main class, the whole application
    '''
    logger = logging.getLogger('TestMain')

    def test_dummy(self):
        '''
        This test establishes a bunch of plain TCP connections against dummy auditor.
        The dummy auditor just acknowledges the fact of connection happening.
        '''
        # these variables will be updated from a hook function invoked from main
        self.got_result_start = 0
        self.got_result = 0
        self.got_result_end = 0
        self.got_bulk_result = 0
        self.nstray = 0

        # the hook function
        def main__handle_result(res):
            '''
            This function overrides main.handle_result() and updates our counters
            '''
            if isinstance(res, ClientAuditStartEvent):
                self.got_result_start = self.got_result_start + 1
            elif isinstance(res, ClientAuditEndEvent):
                self.got_result_end = self.got_result_end + 1
            elif isinstance(res, ClientConnectionAuditResult):
                self.got_result = self.got_result + 1
            elif isinstance(res, ClientAuditResult):
                self.got_bulk_result = self.got_bulk_result + 1
            else:
                self.nstray = self.nstray + 1

        # allocate port
        port = get_next_listener_port()

        # create main, the target of the test
        self.main = Main(['-m', 'dummy', '-l', TEST_LISTENER_ADDR, '-p', port])
        self.main.handle_result = main__handle_result

        # create a client hammering our test listener
        self.client = TCPHammer(peer=(TEST_LISTENER_ADDR, port), nattempts=self.main.auditor_set.len())

        # start server and client
        self.main.start()
        self.client.start()
        self.main.join(timeout=5)

        self.client.stop()

        # make sure we have received expected number of results
        self.assertEquals(self.got_result_start, 1)
        self.assertEquals(self.got_result, self.main.auditor_set.len())
        self.assertEquals(self.got_result_end, 1)
        self.assertEquals(self.got_bulk_result, 1)
        self.assertEquals(self.nstray, 0)

    def test_sslcert_bad_client(self):
        '''
        When plain TCP client connects, we can't tell
        '''

        self.main_test(SSLCERT_MODULE_NAME, TCPHammer, [NegativeAuditResult])

    def test_sslcert_notverifying_client(self):
        self.main_test(SSLCERT_MODULE_NAME, NotVerifyingSSLHammer, [PositiveAuditResult])

    def test_sslcert_verifying_client(self):
        self.main_test(SSLCERT_MODULE_NAME, VerifyingSSLHammer, [NegativeAuditResult])

    def main_test(self, module, client_class, expected_results, debug=0):
        '''
        Abstract tester function.
        '''
        # allocate port
        port = get_next_listener_port()

        # create main, the target of the test
        self.main = Main(['-d', debug, '-m', module, '-l', TEST_LISTENER_ADDR, '-p', port])

        # collect classes of observed audit results
        self.actual_results = []
        self.orig_main__handle_result = self.main.handle_result
        def main__handle_result(res):
            self.orig_main__handle_result(res)
            if isinstance(res, ClientConnectionAuditResult):
                self.actual_results.append(res.__class__)
        self.main.handle_result = main__handle_result

        # create a client hammering the listener
        if client_class != None:
            self.client = client_class(peer=(TEST_LISTENER_ADDR, port), nattempts=self.main.auditor_set.len())
        else:
            self.client = None

        # run the server and the client
        self.main.start()
        if client_class != None:
            self.client.start()
        self.main.join(timeout=5)
        if client_class != None:
            self.client.stop()

        self.assertEquals(expected_results, self.actual_results)

if __name__ == '__main__':
    unittest.main()
