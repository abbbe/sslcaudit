# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, unittest

from sslcaudit.modules.sslcert.ProfileFactory import DEFAULT_CN, SSLProfileSpec_SelfSigned, SSLProfileSpec_IMCA_Signed, SSLProfileSpec_Signed, IM_CA_FALSE_CN, IM_CA_TRUE_CN, IM_CA_NONE_CN, SSLProfileSpec_UserSupplied
from sslcaudit.modules.sslcert.SSLServerHandler import     UNEXPECTED_EOF, ALERT_UNKNOWN_CA, ConnectedGotEOFBeforeTimeout, ConnectedGotRequest
from sslcaudit.test.SSLConnectionHammer import CNVerifyingSSLConnectionHammer
from sslcaudit.test.TCPConnectionHammer import TCPConnectionHammer
from sslcaudit.test.TestConfig import *
from sslcaudit.test.ExternalCommandHammer import CurlHammer
from test import TestModule
from test.TestModule import ECCAR, mk_sslcaudit_argv

LOCALHOST = 'localhost'
HAMMER_HELLO = 'hello'

class TestSSLProtoModule(TestModule.TestModule):
    '''
    Unittests for SSLCert.
    '''
    logger = logging.getLogger('TestSSLProtoModule')


    def test_plain_tcp_client(self):
        # Plain TCP client causes unexpected UNEXPECTED_EOF.
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), UNEXPECTED_EOF),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_USER_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), UNEXPECTED_EOF),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_USER_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), UNEXPECTED_EOF),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_USER_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_USER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN), UNEXPECTED_EOF)
        ]
        self._main_test(
            mk_sslcaudit_argv(),
            TCPConnectionHammer(len(eccars)),
            eccars
        )

    def test_cn_verifying_client(self):
        # CN verifying client only cares about getting a correct CN
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_SelfSigned(LOCALHOST), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), ConnectedGotEOFBeforeTimeout()),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CERT_CN), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CA_CN), ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotRequest(HAMMER_HELLO)),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ]

        self._main_test(
            mk_sslcaudit_argv(user_cn=LOCALHOST),
            CNVerifyingSSLConnectionHammer(len(eccars), HAMMER_HELLO),
            eccars)

    def test_curl(self):
        # curl does all the checks
        eccars = [
            # user-supplied certificate
            ECCAR(SSLProfileSpec_UserSupplied(TEST_USER_CERT_CN), ConnectedGotEOFBeforeTimeout()),

            # self-signed certificates
            ECCAR(SSLProfileSpec_SelfSigned(DEFAULT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_SelfSigned(LOCALHOST), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_SelfSigned(TEST_SERVER_CN), ALERT_UNKNOWN_CA),

            # signed by user-supplied certificate
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CERT_CN), ALERT_UNKNOWN_CA),

            # signed by user-supplied CA
            ECCAR(SSLProfileSpec_Signed(DEFAULT_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),
            ECCAR(SSLProfileSpec_Signed(LOCALHOST, TEST_USER_CA_CN), ConnectedGotRequest()),
            ECCAR(SSLProfileSpec_Signed(TEST_SERVER_CN, TEST_USER_CA_CN), ConnectedGotEOFBeforeTimeout()),

            # default CN, signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(DEFAULT_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),

            # user-supplied CN signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(LOCALHOST, IM_CA_TRUE_CN, TEST_USER_CA_CN), ConnectedGotRequest()),

            # replica of server certificate signed by user-supplied CA, with an intermediate CA
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_NONE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_FALSE_CN, TEST_USER_CA_CN), ALERT_UNKNOWN_CA),
            ECCAR(SSLProfileSpec_IMCA_Signed(TEST_SERVER_CN, IM_CA_TRUE_CN, TEST_USER_CA_CN),
                ConnectedGotEOFBeforeTimeout()),
            ]

        self._main_test(
            mk_sslcaudit_argv(user_cn=LOCALHOST),
            CurlHammer(len(eccars), TEST_USER_CA_CERT_FILE),
            eccars
        )


if __name__ == '__main__':
    TestModule.init_logging()
    unittest.main()
