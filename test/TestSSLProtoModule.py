# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, unittest, re

from sslcaudit.modules.sslcert.ProfileFactory import DEFAULT_CN, SSLProfileSpec_SelfSigned, SSLProfileSpec_IMCA_Signed, SSLProfileSpec_Signed, IM_CA_FALSE_CN, IM_CA_TRUE_CN, IM_CA_NONE_CN, SSLProfileSpec_UserSupplied
from sslcaudit.modules.sslcert.SSLServerHandler import     UNEXPECTED_EOF, ALERT_UNKNOWN_CA, ConnectedGotEOFBeforeTimeout, ConnectedGotRequest
from sslcaudit.modules.sslproto.suites import SUITES
from sslcaudit.modules.sslproto.ProfileFactory import SSLServerProtoSpec
from sslcaudit.modules.sslproto.ServerHandler import Connected
from sslcaudit.test.ExternalCommandHammer import CurlHammer, OpenSSLHammer
from sslcaudit.test.TCPConnectionHammer import TCPConnectionHammer
from sslcaudit.test.TestConfig import *
from test import TestModule
from test.TestModule import ECCAR, mk_sslcaudit_argv
from sslcaudit.modules import sslproto

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
            for cipher in sslproto.DEFAULT_CIPHER_SUITES:
                eccars.append(ECCAR(SSLServerProtoSpec(proto, cipher), UNEXPECTED_EOF))

        self._main_test(
            ['-m', 'sslproto'],
            TCPConnectionHammer(len(eccars)),
            eccars
        )

    def test_plain_tcp_client_timeout(self):
        # Plain TCP client causes unexpected UNEXPECTED_EOF.
        eccars = []
        for proto in sslproto.get_supported_protocols():
            for cipher in sslproto.DEFAULT_CIPHER_SUITES:
                if proto == 'sslv2':
                    expected_error = 'SSL_ERROR_ZERO_RETURN'
                else:
                    expected_error = 'SSL_ERROR_SYSCALL'
                eccars.append(ECCAR(SSLServerProtoSpec(proto, cipher), expected_error))

        self._main_test(
            ['-m', 'sslproto'],
            TCPConnectionHammer(len(eccars), delay_before_close=30),
            eccars
        )

    def test_curl_works_with_sslv2_and_export_ciphers(self):
        # curl is expected to work with SSLv2 and weak ciphers
        eccars = []
        there_are_export_ciphers = False
        protos = sslproto.get_supported_protocols()
        for proto in protos:
            for cipher in sslproto.DEFAULT_CIPHER_SUITES:
                if cipher == sslproto.EXPORT_CIPHER:
                    there_are_export_ciphers = True

                if proto == 'sslv2':
                    expected_res = ALERT_NON_SSLV2_INITIAL_PACKET
                elif proto == 'sslv3':
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

    def _test_openssl_accepts_default_ciphers_for_proto(self, proto):
        eccars = []
        for cipher in sslproto.DEFAULT_CIPHER_SUITES:
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

    def _test_openssl_accepts_selected_proto_cipher(self, selected_proto, selected_cipher):
        eccars = []
        for cipher in sslproto.get_ciphers(selected_proto):
            if cipher == selected_cipher:
                expected_res = Connected()
            else:
                expected_res = ALERT_NO_SHARED_CIPHER
            eccars.append(ECCAR(SSLServerProtoSpec(selected_proto, cipher), expected_res=expected_res))
        self._main_test(
            ['-m', 'sslproto', '--protocols', selected_proto, '--iterate-suites', '-d', '1'],
            OpenSSLHammer(len(eccars), cipher=selected_cipher),
            eccars
        )

def create_per_proto_tests():
    def _(self, proto):
        self._test_openssl_accepts_default_ciphers_for_proto(proto)

    for proto in sslproto.get_supported_protocols():
        setattr(TestSSLProtoModule, "test_openssl_accepts_all_ciphers_for_proto_%s" % proto,
            lambda self, proto=proto: _(self, proto))

def create_per_cipher_tests():
    def _(self, proto, cipher):
        self._test_openssl_accepts_selected_proto_cipher(proto, cipher)

    for proto in sslproto.get_supported_protocols():
        ciphers = sslproto.get_ciphers(proto)
        for cipher in ciphers:
            cipher_slug_name = re.sub('-', '_', cipher)
            setattr(TestSSLProtoModule, "test_openssl_accepts_proto_%s_cipher_%s" % (proto, cipher_slug_name),
                lambda self, proto=proto, cipher=cipher: _(self, proto, cipher))

create_per_proto_tests()
create_per_cipher_tests()

if __name__ == '__main__':
    TestModule.init_logging()
    unittest.main()
