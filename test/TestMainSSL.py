import logging
from unittest.case import TestCase
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult, NegativeAuditResult, PositiveAuditResult
from src.ClientAuditor.SSL import SSLClientAuditorSet
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
        '''
        Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA
        '''
        self._main_test("bad_client", SSLCERT_MODULE_NAME, TCPHammer(),
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                NegativeAuditResult(SSLClientAuditorSet.UNEXPECTED_EOF, SSLClientAuditorSet.UNKNOWN_CA))])

    def test_notverifying_client(self):
        '''
        A client which fails to verify the chain of trust reports no error
        '''
        self._main_test('not_verifying', SSLCERT_MODULE_NAME, NotVerifyingSSLHammer(),
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                NegativeAuditResult(SSLClientAuditorSet.OK, SSLClientAuditorSet.UNKNOWN_CA))])

    #    def test_cn_verifying_client1(self):
    #        '''
    #        A client which only verifies CN, but not the chain of trust will ?
    #        Must return CN_MISMATCH
    #        '''
    #        self._main_test('cn_verifying1', SSLCERT_MODULE_NAME, CNVerifyingSSLHammer(DEFAULT_X509_SELFSIGNED_CERT_CN),
    #            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
    #                PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])

    def test_verifying_client(self):
        '''
        A client which properly verifies the certificate reports UNKNOWN_CA
        '''
        self._main_test('verifying_all', SSLCERT_MODULE_NAME, VerifyingSSLHammer(TestConfig.SSL_CLIENT_EXPECTED_CN),
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])


    # ------------------------------------------------------------------------------------

    def test_notverifying_client__vs__usercert(self):
        ''' A client which verifies nothing is expected to have no problem '''
        r__def_cn_selfsigned = ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
            NegativeAuditResult(SSLClientAuditorSet.UNKNOWN_CA, SSLClientAuditorSet.UNKNOWN_CA))

        r__usercert = ClientConnectionAuditResult('usercert', '127.0.0.1',
            NegativeAuditResult(SSLClientAuditorSet.UNKNOWN_CA, SSLClientAuditorSet.UNKNOWN_CA))

#        self._main_test('notverifying',
#            [], NotVerifyingSSLHammer(),
#            [r__def_cn_selfsigned])
#
##        self._main_test('notverifying__vs__usercert',
##            ['--cert', 'test/sslcaudit-test.gremwell.com-key.pem'], NotVerifyingSSLHammer(),
##            [r__def_cn_selfsigned, r__usercert])


    def test_verifying_client__vs__good(self):
        '''
        A client which properly verifies the certificate reports UNKNOWN_CA
        '''
        self._main_test('verifying_all__vs__good',
            SSLCERT_MODULE_NAME,
            VerifyingSSLHammer(TestConfig.SSL_CLIENT_EXPECTED_CN),
            [ClientConnectionAuditResult('def_cn/self_signed', '127.0.0.1',
                PositiveAuditResult(SSLClientAuditorSet.UNKNOWN_CA))])


    # ------------------------------------------------------------------------------------
    def setUp(self):
        self.main = None

    def tearDown(self):
        if self.main != None: self.main.stop()

    def _main_test(self, test_name, args, hammer, expected_results, debug=0):
        '''
        This is a main worker function. It allocates external resources and launches threads,
        to make sure they are freed this function was to be called exactly once per test method,
        to allow tearDown() method to cleanup properly.
        '''
        self._main_test_init(test_name, args, hammer, debug)
        self._main_test_do(expected_results)

    def _main_test_init(self, test_name, args, ssl_hammer, debug=0):
        # allocate port
        port = TestConfig.get_next_listener_port()

        # create main, the target of the test
        main_args = ['-d', debug, '-l', TestConfig.TEST_LISTENER_ADDR, '-N', test_name, '-p', port]
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
        self.hammer = ssl_hammer
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

