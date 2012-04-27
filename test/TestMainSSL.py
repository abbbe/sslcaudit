import logging
from unittest.case import TestCase
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult, NegativeAuditResult, PositiveAuditResult
from src.ClientAuditor.SSL import SSLClientAuditorSet
from src.ClientAuditor.SSL.SSLClientAuditorSet import UNEXPECTED_EOF, UNKNOWN_CA, OK
from src.Main import SSLCERT_MODULE_NAME, Main
from src.Test import TestConfig
from src.Test.SSLHammer import NotVerifyingSSLHammer, VerifyingSSLHammer
from src.Test.TCPHammer import TCPHammer

class TestMainSSL(TestCase):
    '''
    Unittests for SSL.
    '''
    logger = logging.getLogger('TestMainSSL')

    def test_bad_client(self):
        ''' Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA '''
        self._main_test(['--cn', "dummy"], TCPHammer(),
            [
                ClientConnectionAuditResult(('default_cn', 'self'), '127.0.0.1', NegativeAuditResult(UNEXPECTED_EOF, UNKNOWN_CA)),
                ClientConnectionAuditResult(('user_cn', 'self'), '127.0.0.1', NegativeAuditResult(UNEXPECTED_EOF, UNKNOWN_CA))
            ])

    def test_notverifying_client(self):
        ''' A client which fails to verify the chain of trust reports no error '''
        self._main_test(['--cn', "dummy"], NotVerifyingSSLHammer(),
            [
                ClientConnectionAuditResult(('default_cn', 'self'), '127.0.0.1', NegativeAuditResult(OK, UNKNOWN_CA)),
                ClientConnectionAuditResult(('user_cn', 'self'), '127.0.0.1', NegativeAuditResult(OK, UNKNOWN_CA))
            ])

    def test_verifying_client(self):
        ''' A client which properly verifies the certificate reports UNKNOWN_CA '''
        self._main_test(['--cn', "dummy"], VerifyingSSLHammer(TestConfig.SSL_CLIENT_EXPECTED_CN),
            [
                ClientConnectionAuditResult(('default_cn', 'self'), '127.0.0.1', PositiveAuditResult(UNKNOWN_CA)),
                ClientConnectionAuditResult(('user_cn', 'self'), '127.0.0.1', PositiveAuditResult(UNKNOWN_CA))
            ])

#    #    def test_cn_verifying_client1(self):
#    #        '''
#    #        A client which only verifies CN, but not the chain of trust will ?
#    #        Must return CN_MISMATCH
#    #        '''
#    #        self._main_test('cn_verifying1', SSLCERT_MODULE_NAME, CNVerifyingSSLHammer(DEFAULT_X509_SELFSIGNED_CERT_CN),
#    #            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
#    #                PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])
#
#
#    # ------------------------------------------------------------------------------------
#
#    def xtest_verifying_client__vs__good(self):
#        '''
#        A client which properly verifies the certificate reports UNKNOWN_CA
#        '''
#        self._main_test([], VerifyingSSLHammer(TestConfig.SSL_CLIENT_EXPECTED_CN),
#            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
#                PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])
#

    # ------------------------------------------------------------------------------------
    def setUp(self):
        self.main = None

    def tearDown(self):
        if self.main != None: self.main.stop()

    def _main_test(self, args, hammer, expected_results):
        '''
        This is a main worker function. It allocates external resources and launches threads,
        to make sure they are freed this function was to be called exactly once per test method,
        to allow tearDown() method to cleanup properly.
        '''
        self._main_test_init(args, hammer)
        self._main_test_do(expected_results)

    def _main_test_init(self, args, hammer):
        # allocate port
        port = TestConfig.get_next_listener_port()

        # create main, the target of the test
        test_name = "%s %s" % (args, hammer)
        main_args = ['-l', TestConfig.TEST_LISTENER_ADDR, '-N', test_name, '-p', port]
        if isinstance(args, basestring):
            main_args.extend(['-m', args]) # for backward compatibility
        else:
            main_args.extend(args)
        self.main = Main(main_args)

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
        self.hammer = hammer
        if self.hammer != None:
            self.hammer.init_tcp((TestConfig.TEST_LISTENER_ADDR, port), self.main.auditor_set.len())

    def _main_test_do(self, expected_results):
        # run the server
        self.main.start()

        # start the hammer if any
        if self.hammer != None:    self.hammer.start()

        # wait for main to finish its job
        try:
            self.main.join(timeout=TestConfig.MAIN_JOIN_TIMEOUT)
            # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        finally:
            # stop the hammer if any
            if self.hammer != None:    self.hammer.stop()

            # stop the server
            self.main.stop()

        self.assertEquals(expected_results, self.actual_results)

