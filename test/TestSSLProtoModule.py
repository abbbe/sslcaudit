# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, unittest

from sslcaudit.modules.sslcert.ProfileFactory import DEFAULT_CN, SSLProfileSpec_SelfSigned, SSLProfileSpec_IMCA_Signed, SSLProfileSpec_Signed, IM_CA_FALSE_CN, IM_CA_TRUE_CN, IM_CA_NONE_CN, SSLProfileSpec_UserSupplied
from sslcaudit.modules.sslcert.SSLServerHandler import     UNEXPECTED_EOF, ALERT_UNKNOWN_CA, ConnectedGotEOFBeforeTimeout, ConnectedGotRequest
from sslcaudit.modules.sslproto.ProfileFactory import SSLServerProtoSpec
from sslcaudit.modules.sslproto.ServerHandler import Connected
from sslcaudit.test.ExternalCommandHammer import CurlHammer, OpenSSLHammer
from sslcaudit.test.TCPConnectionHammer import TCPConnectionHammer
from sslcaudit.test.TestConfig import *
from test import TestModule
from test.TestModule import ECCAR, mk_sslcaudit_argv
from sslcaudit.modules import sslproto

LOCALHOST = 'localhost'
HAMMER_HELLO = 'hello'

ALERT_NO_SHARED_CIPHER = 'no shared cipher'
ALERT_SSLV3_BAD_CERTIFICATE = 'sslv3 alert bad certificate'
ALERT_NON_SSLV2_INITIAL_PACKET = 'non sslv2 initial packet'

class TestSSLProtoModule(TestModule.TestModule):
    '''
    Unittests for SSLCert.
    '''
    logger = logging.getLogger('TestSSLProtoModule')


    def test_plain_tcp_client(self):
        # Plain TCP client causes unexpected UNEXPECTED_EOF.
        eccars = []
        for proto in sslproto.get_supported_protocols():
            for cipher in sslproto.ALL_CIPHERS:
                eccars.append(ECCAR(SSLServerProtoSpec(proto, cipher), UNEXPECTED_EOF))

        self._main_test(
            ['-m', 'sslproto'],
            TCPConnectionHammer(len(eccars)),
            eccars
        )

    def test_curl_rejects_sslv2_and_export_ciphers(self):
        # curl (and any other proper SSL client for that purpose) is expected to reject SSLv2 and weak ciphers
        eccars = []
        there_are_export_ciphers = False
        protos = sslproto.get_supported_protocols()
        for proto in protos:
            for cipher in sslproto.ALL_CIPHERS:
                if proto == 'sslv2':
                    expected_res = ALERT_NON_SSLV2_INITIAL_PACKET
                elif cipher == sslproto.EXPORT_CIPHER:
                    # we expect curl to refuse connecting to server offering an export-grade ciphers
                    expected_res = ALERT_NO_SHARED_CIPHER
                    there_are_export_ciphers = True
                else:
                    # we expect curl to establish the connection to a server offering non-export cipher
                    if proto == 'sslv3':
                        expected_res = ALERT_SSLV3_BAD_CERTIFICATE
                    else:
                        expected_res = ALERT_UNKNOWN_CA
                eccars.append(ECCAR(SSLServerProtoSpec(proto, cipher), expected_res=expected_res))
        self.assertTrue(there_are_export_ciphers)
        self._main_test(
            ['-m', 'sslproto'],
            CurlHammer(len(eccars)),
            eccars
        )

    def test_opensssl_accepts_all_ciphers(self):
        # openssl client is expected to connect to anything
        for proto in sslproto.get_supported_protocols():
            self._test_opensssl_accepts_all_ciphers_for_proto(proto)

    def _test_opensssl_accepts_all_ciphers_for_proto(self, proto):
            eccars = []
            for cipher in sslproto.ALL_CIPHERS:
                expected_res = Connected()
                eccars.append(ECCAR(SSLServerProtoSpec(proto, cipher), expected_res=expected_res))

            if proto == 'sslv2':
                openssl_args = '-ssl2'
            elif proto == 'sslv3':
                openssl_args = '-ssl3'
            elif proto == 'tlsv1':
                openssl_args = '-tls1'
            else:
                raise ValueError()

            self._main_test(
                ['-m', 'sslproto', '--protocols', proto],
                OpenSSLHammer(len(eccars), [openssl_args]),
                eccars
            )

if __name__ == '__main__':
    TestModule.init_logging()
    unittest.main()
