''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, unittest
from src.CertFactory import SELFSIGNED
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.SSL.SSLClientAuditorSet import DEFAULT_CN
from src.ClientAuditor.SSL.SSLClientConnectionAuditor import  UNEXPECTED_EOF, UNKNOWN_CA, ConnectedReadTimeout
from src.Main import Main
from src.Test import TestConfig
from src.Test.SSLHammer import NotVerifyingSSLHammer, VerifyingSSLHammer
from src.Test.TCPHammer import TCPHammer
from src.Test.TestConfig import *

TEST_DEBUG = 0

class ExpectedSSLClientConnectionAuditResult(object):
    def __init__(self, auditor_name, client_id, res):
        self.auditor_name = auditor_name
        self.client_id = client_id
        self.res = res

    def matches(self, audit_res):
        '''
        Given an actual audit result instance (ClientConnectionAuditResult) checks if it matches current expectations.
        '''
        actual_auditor_name = audit_res.auditor.name
        if actual_auditor_name != self.auditor_name:
            return False

        actual_client_id = audit_res.conn.get_client_id()
        if actual_client_id != self.client_id:
            return False

        #actual_res = str(audit_res.res)
        #expected_res = str(self.res)
        #if actual_res != expected_res:
        if self.res == audit_res.res:
            return True
        else:
            return False

        return True

    def __str__(self):
        return "ECCAR(%s, %s, %s)" % (self.auditor_name, self.client_id, self.res)


class TestMainSSL(unittest.TestCase):
    '''
    Unittests for SSL.
    '''
    logger = logging.getLogger('TestMainSSL')

    HAMMER_ATTEMPTS = 10

    def xtest_bad_client1(self):
        ''' Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA '''
        self._main_test(
            [
                '-d', TEST_DEBUG,
                '--user-cn', TEST_USER_CN,
                '--user-ca-cert', TEST_USER_CA_CERT_FILE,
                '--user-ca-key', TEST_USER_CA_KEY_FILE
            ],
            TCPHammer(),
            [
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (DEFAULT_CN, SELFSIGNED), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_USER_CN, SELFSIGNED), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (DEFAULT_CN, TEST_USER_CA_CN), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_USER_CN, TEST_USER_CA_CN), '127.0.0.1', UNEXPECTED_EOF)
            ])

    #    def test_bad_client2(self):
    #        ''' Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA '''
    #        self._main_test(
    #            [
    #                '--user-cert', TEST_USER_CERT_FILE,
    #                '--user-key', TEST_USER_KEY_FILE,
    #                '--no-user-cert-sign'
    #            ],
    #            TCPHammer(),
    #            [
    #                ExpectedSSLClientConnectionAuditResult((TEST_USER_CERT_CN, None), '127.0.0.1', UNEXPECTED_EOF),
    #                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, SELFSIGNED), '127.0.0.1', UNEXPECTED_EOF),
    #            ])

    def test_notverifying_client(self):
        ''' A client which fails to verify the chain of trust reports no error '''
        self._main_test(
            [
                '--user-cn', TEST_USER_CN,
                '--server', TEST_SERVER
            ],
            NotVerifyingSSLHammer(),
            [
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (DEFAULT_CN, SELFSIGNED), '127.0.0.1', ConnectedReadTimeout(None)),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_USER_CN, SELFSIGNED), '127.0.0.1', ConnectedReadTimeout(None)),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_SERVER_CN, SELFSIGNED), '127.0.0.1', ConnectedReadTimeout(None))
            ])

    def xtest_verifying_client(self):
        ''' A client which properly verifies the certificate reports UNKNOWN_CA '''
        self._main_test(
            [
                '--user-cn', TEST_USER_CN,
                '--server', TEST_SERVER
            ],
            VerifyingSSLHammer(TEST_USER_CN),
            [
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (DEFAULT_CN, SELFSIGNED), '127.0.0.1', UNKNOWN_CA),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_USER_CN, SELFSIGNED), '127.0.0.1', UNKNOWN_CA),
                ExpectedSSLClientConnectionAuditResult(
                    "sslcert(('%s', '%s'))" % (TEST_SERVER_CN, SELFSIGNED), '127.0.0.1', UNKNOWN_CA)
            ])

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
        test_name = "%s %s" % (hammer, args)
        main_args = ['-l', '%s:%d' % (TestConfig.TEST_LISTENER_ADDR, port)]
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
            self.hammer.init_tcp((TestConfig.TEST_LISTENER_ADDR, port), self.HAMMER_ATTEMPTS)

    def _main_test_do(self, expected_results):
        # run the server
        self.main.start()

        # start the hammer if any
        if self.hammer != None:    self.hammer.start()

        # wait for main to finish its job
        try:
            self.main.join(timeout=TestConfig.TEST_MAIN_JOIN_TIMEOUT)
            # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        finally:
            # stop the hammer if any
            if self.hammer != None:    self.hammer.stop()

            # stop the server
            self.main.stop()

        # check if the actual results match expected ones
        if len(expected_results) != len(self.actual_results):
            mismatch = True
            print "! length mismatch len(er)=%d, len(ar)=%d" % (len(expected_results), len(self.actual_results))
            for er in expected_results: print "er=%s" % er
            for ar in self.actual_results: print "ar=%s" % ar
        else:
            mismatch = False
            for i in range(len(expected_results)):
                er = expected_results[i]
                ar = self.actual_results[i]
                if not er.matches(ar):
                    print "! mismatch\n\ter=%s\n\tar=%s" % (er, ar)
                    mismatch = True
        self.assertFalse(mismatch)

if __name__ == '__main__':
    logging.basicConfig()
    unittest.main()

