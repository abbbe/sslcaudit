''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
import unittest
from src.CertFactory import *
from src.Test.TestConfig import *

class TestCertFactory(unittest.TestCase):
    def setUp(self):
        self.cert_factory = CertFactory()

    def test_mk_simple_selfsigned_cert(self):
        certnkey = self.cert_factory.mk_simple_selfsigned_certnkey(DEFAULT_X509_CN, DEFAULT_X509_C, DEFAULT_X509_O)
        good_subj = 'CN=%s, C=%s, O=%s' % (DEFAULT_X509_CN, DEFAULT_X509_C, DEFAULT_X509_O)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text())

    def test_grab_server_x509_cert1(self):
        self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT))

    def test_grab_server_x509_cert2(self):
        server = "%s:%d" % (TEST_SERVER_HOST, TEST_SERVER_PORT)
        self.cert_factory.grab_server_x509_cert(server)

    def test_mk_server_replica_cert(self):
        '''
        This test grabs a certificate from the test server and
        '''
        server_cert = self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT))
        ss_replica_certnkey = self.cert_factory.mk_selfsigned_replica_certnkey(server_cert)
        self.assertEqual(server_cert.get_subject().as_text(), ss_replica_certnkey.cert.get_subject().as_text())
