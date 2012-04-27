import logging
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor
from src.ClientAuditor.SSL import SSLClientAuditorSet

logging.basicConfig()

import unittest

from src.ClientAuditor.ClientConnectionAuditEvent import ClientAuditEndEvent, ClientAuditStartEvent, ClientConnectionAuditResult, NegativeAuditResult, PositiveAuditResult
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
    MAIN_JOIN_TIMEOUT = 5

    def xtest_dummy(self):
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

        # create a client hammering our test listener
        self.hammer = TCPHammer(peer=(TEST_LISTENER_ADDR, port))

        # create main, the target of the test
        self.main = Main(['-m', 'dummy', '-l', TEST_LISTENER_ADDR, '-p', port])
        self.main.handle_result = main__handle_result

        # tell the hammer how many attempts to make exactly
        self.hammer.nattempts = self.main.auditor_set.len()

        # start server and client
        self.main.start()
        self.hammer.start()

        self.main.join(timeout=5)
        self.hammer.stop()
        self.main.stop()

        # make sure we have received expected number of results
        self.assertEquals(self.got_result_start, 1)
        self.assertEquals(self.got_result, self.main.auditor_set.len())
        self.assertEquals(self.got_result_end, 1)
        self.assertEquals(self.got_bulk_result, 1)
        self.assertEquals(self.nstray, 0)

    def test_sslcert_bad_client(self):
        '''
        Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA
        '''
        self._main_test(SSLCERT_MODULE_NAME, TCPHammer,
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                NegativeAuditResult(SSLClientAuditorSet.UNEXPECTED_EOF, SSLClientAuditorSet.UNKNOWN_CA))])

    def test_sslcert_notverifying_client(self):
        '''
        A client which fails to verify the chain of trust reports no error
        '''
        self._main_test(SSLCERT_MODULE_NAME, NotVerifyingSSLHammer,
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                NegativeAuditResult(SSLClientAuditorSet.OK, SSLClientAuditorSet.UNKNOWN_CA))])

    def test_sslcert_cn_verifying_client(self):
        '''
        A client which only verifies CN will report OK
        '''
        self._main_test(SSLCERT_MODULE_NAME, VerifyingSSLHammer,
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1', PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])

    def test_sslcert_verifying_client(self):
        '''
        A client which properly verifies the certificate reports UNKNOWN_CA
        '''
        self._main_test(SSLCERT_MODULE_NAME, VerifyingSSLHammer,
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1', PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])

    def _main_test(self, module, hammer_class, expected_results, debug=0):
        '''
        This is a main worker function. It allocates external resources and launches threads,
        to make sure they are freed this function was to be called exactly once per test method,
        to allow tearDown() method to cleanup properly.
        '''
        self._main_test_init(module, hammer_class, debug)
        self._main_test_do(expected_results)

    def _main_test_init(self, module, hammer_class, debug=0):
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
                self.actual_results.append(res)
            else:
                pass # ignore events print res
        self.main.handle_result = main__handle_result

        # create a client hammering the listener
        if hammer_class != None:
            self.hammer = hammer_class(peer=(TEST_LISTENER_ADDR, port), nattempts=self.main.auditor_set.len())
        else:
            self.hammer = None

    def _main_test_do(self, expected_results):
        # run the server
        self.main.start()

        # start the hammer if any
        if self.hammer != None:    self.hammer.start()

        # wait for main to finish its job
        try:
            self.main.join(timeout=self.MAIN_JOIN_TIMEOUT)
            # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        finally:
            # stop the hammer if any
            if self.hammer != None:    self.hammer.stop()

            # stop the server
            self.main.stop()

        self.assertEquals(expected_results, self.actual_results)

    def setUp(self):
        self.main = None

    def tearDown(self):
        if self.main != None: self.main.stop()

if __name__ == '__main__':
    unittest.main()
