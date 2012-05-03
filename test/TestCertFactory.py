''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
import tempfile

import unittest
from src.core.CertFactory import *
from src.core.FileBag import FileBag
from src.test.TestConfig import *

class TestCertFactory(unittest.TestCase):
    def setUp(self):
        self.file_bag = FileBag('testcertfactory', use_tempdir=True)
        self.cert_factory = CertFactory(self.file_bag)

    def test_new_selfsigned_certnkey(self):
        certnkey = self.cert_factory.new_certnkey(TEST_USER_CN, ca_certnkey=None)

        good_subj = 'CN=%s, C=%s, O=%s' % (TEST_USER_CN, DEFAULT_X509_C, DEFAULT_X509_ORG)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text())
        self.assertEqual(good_subj, certnkey.cert.get_issuer().as_text())

    def test_new_signed_certnkey(self):
        ca_certnkey = self.cert_factory.load_certnkey_files(
            TEST_USER_CA_CERT_FILE, TEST_USER_CA_KEY_FILE)
        certnkey = self.cert_factory.new_certnkey(TEST_USER_CN, ca_certnkey=ca_certnkey)

        good_subj = 'CN=%s, C=%s, O=%s' % (TEST_USER_CN, DEFAULT_X509_C, DEFAULT_X509_ORG)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text())
        self.assertEqual(certnkey.cert.get_issuer().as_text(), ca_certnkey.cert.get_subject().as_text())

    def test_mk_selfsigned_server_replica_cert(self):
        '''
        This test grabs a certificate from the test server and self-signs it
        '''
        server_cert = self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT))
        ss_replica_certnkey = self.cert_factory.mk_signed_replica_certnkey(server_cert)
        self.assertEqual(server_cert.get_subject().as_text(), ss_replica_certnkey.cert.get_subject().as_text())
        self.assertEqual(ss_replica_certnkey.cert.get_issuer().as_text(), ss_replica_certnkey.cert.get_subject().as_text())

    def test_mk_signed_server_replica_cert(self):
        server_cert = self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT))
        ca_certnkey = self.cert_factory.load_certnkey_files(TEST_USER_CA_CERT_FILE, TEST_USER_CA_KEY_FILE)
        ss_replica_certnkey = self.cert_factory.mk_signed_replica_certnkey(server_cert, ca_certnkey)
        self.assertEqual(
            ca_certnkey.cert.get_subject().as_text(),
            ss_replica_certnkey.cert.get_issuer().as_text())

    def test_grab_server_x509_cert1(self):
        self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT))

    def test_grab_server_x509_cert2(self):
        server = "%s:%d" % (TEST_SERVER_HOST, TEST_SERVER_PORT)
        self.cert_factory.grab_server_x509_cert(server)


if __name__ == '__main__':
    unittest.main()
