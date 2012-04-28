''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, unittest
from ovs.reconnect import CONNECT
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.SSL.SSLClientAuditorSet import UNEXPECTED_EOF, UNKNOWN_CA, DEFAULT_CN
from src.Main import Main
from src.Test import TestConfig
from src.Test.SSLHammer import NotVerifyingSSLHammer, VerifyingSSLHammer
from src.Test.TCPHammer import TCPHammer
from src.Test.TestConfig import *

SELF = 'SELF' # XXX to be moved away

TEST_USER_CERT_CN = 'sslcaudit-test.gremwell.com'
TEST_USER_CERT_FILE = 'test/sslcaudit-test.gremwell.com-cert.pem'
TEST_USER_KEY_FILE = 'test/sslcaudit-test.gremwell.com-key.pem'

TEST_USER_CA_CN = 'sslcaudit-test'
TEST_USER_CA_CERT_FILE = 'test/sslcaudit-test-cacert.pem'
TEST_USER_CA_KEY_FILE = 'test/sslcaudit-test-cakey.pem'

class ExpectedSSLClientConnectionAuditResult(object):
    def __init__(self, cert_name, client_id, res):
        self.cert_name = cert_name
        self.client_id = client_id
        self.res = res

    def matches(self, audit_res):
        '''
        Given an actual audit result instance (ClientConnectionAuditResult) checks if it matches current expectations.
        '''
        actual_cert_name = audit_res.auditor.certnkey.name
        if actual_cert_name != self.cert_name: return False

        actual_client_id = audit_res.conn.get_client_id()
        if actual_client_id != self.client_id: return False

        return audit_res.res == self.res

    def __str__(self):
        return "%s %s %s" % (self.cert_name, self.client_id, self.res)


class TestMainSSL(unittest.TestCase):
    '''
    Unittests for SSL.
    '''
    logger = logging.getLogger('TestMainSSL')

    def test_bad_client1(self):
        ''' Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA '''
        self._main_test(
            [
                '--user-cn', TEST_USER_CN,
                '--user-ca-cert', TEST_USER_CA_CERT_FILE,
                '--user-ca-key', TEST_USER_CA_KEY_FILE
            ],
            TCPHammer(),
            [
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, SELF), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, SELF), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, TEST_USER_CA_CN), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, TEST_USER_CA_CN), '127.0.0.1', UNEXPECTED_EOF)
            ])

    def test_bad_client2(self):
        ''' Plain TCP client causes unexpected UNEXPECTED_EOF instead of UNKNOWN_CA '''
        self._main_test(
            [
                '--user-cert', TEST_USER_CERT_FILE,
                '--user-key', TEST_USER_KEY_FILE
            ],
            TCPHammer(),
            [
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, SELF), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, SELF), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, TEST_USER_CERT_CN), '127.0.0.1', UNEXPECTED_EOF),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, TEST_USER_CERT_CN), '127.0.0.1', UNEXPECTED_EOF)
            ])

    def test_notverifying_client(self):
        ''' A client which fails to verify the chain of trust reports no error '''
        self._main_test(
            [
                '--user-cn', TEST_USER_CN,
                '--server', TEST_SERVER
            ],
            NotVerifyingSSLHammer(),
            [
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, SELF), '127.0.0.1', CONNECT),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, SELF), '127.0.0.1', CONNECT),
                ExpectedSSLClientConnectionAuditResult((TEST_SERVER_CN, SELF), '127.0.0.1', CONNECT)
            ])

    def test_verifying_client(self):
        ''' A client which properly verifies the certificate reports UNKNOWN_CA '''
        self._main_test(
            [
                '--user-cn', TEST_USER_CN,
                '--server', TEST_SERVER
            ],
            VerifyingSSLHammer(TEST_USER_CN),
            [
                ExpectedSSLClientConnectionAuditResult((DEFAULT_CN, SELF), '127.0.0.1', UNKNOWN_CA),
                ExpectedSSLClientConnectionAuditResult((TEST_USER_CN, SELF), '127.0.0.1', UNKNOWN_CA),
                ExpectedSSLClientConnectionAuditResult((TEST_SERVER_CN, SELF), '127.0.0.1', UNKNOWN_CA)
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
            self.main.join(timeout=TestConfig.TEST_MAIN_JOIN_TIMEOUT)
            # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        finally:
            # stop the hammer if any
            if self.hammer != None:    self.hammer.stop()

            # stop the server
            self.main.stop()

        self.assertEquals(len(expected_results), len(self.actual_results))
        for i in range(len(expected_results)):
            er = expected_results[i]
            ar = self.actual_results[i]
            if not er.matches(ar):
                print "* mismatch er=%s, ar=%s" % (er, ar)


if __name__ == '__main__':
    unittest.main()

