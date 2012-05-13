''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
import tempfile

import unittest
from sslcaudit.core.CertFactory import *
from sslcaudit.core.FileBag import FileBag
from sslcaudit.test.TestConfig import *

SSL_PROTO = 'sslv23'

class TestCertFactory(unittest.TestCase):
    def setUp(self):
        self.file_bag = FileBag('testcertfactory', use_tempdir=True)
        self.cert_factory = CertFactory(self.file_bag)

    def test__mk_certreq_n_keys(self):
        certreq = self.cert_factory.mk_certreq_n_keys(TEST_USER_CN)
        # check subject
        good_subj = 'CN=%s, C=%s, O=%s' % (TEST_USER_CN, DEFAULT_X509_C, DEFAULT_X509_ORG)
        self.assertEqual(good_subj, certreq[0].get_subject().as_text())

    def test__load_certnkey_files(self):
        ca_certnkey = self.cert_factory.load_certnkey_files(TEST_USER_CA_CERT_FILE, TEST_USER_CA_KEY_FILE)
        # check CN of loaded certificate
        self.assertEqual(TEST_USER_CA_CN, ca_certnkey.cert.get_subject().CN)

    def test_create_selfsigned(self):
        certreq = self.cert_factory.mk_certreq_n_keys(TEST_USER_CN)
        certnkey = self.cert_factory.sign_cert_req(certreq, None)
        # check subject and issuer of self-signed certificate
        good_subj = 'CN=%s, C=%s, O=%s' % (TEST_USER_CN, DEFAULT_X509_C, DEFAULT_X509_ORG)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text())
        self.assertEqual(good_subj, certnkey.cert.get_issuer().as_text())

    def test_create_signed(self):
        # create signed certificate
        certreq = self.cert_factory.mk_certreq_n_keys(TEST_USER_CN)
        ca_certnkey = self.cert_factory.load_certnkey_files(TEST_USER_CA_CERT_FILE, TEST_USER_CA_KEY_FILE)
        certnkey = self.cert_factory.sign_cert_req(certreq, ca_certnkey)
        # check subject and issuer of signed certificate
        good_subj = 'CN=%s, C=%s, O=%s' % (TEST_USER_CN, DEFAULT_X509_C, DEFAULT_X509_ORG)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text())
        self.assertEqual(certnkey.cert.get_issuer().as_text(), ca_certnkey.cert.get_subject().as_text())

    def test__mk_signed_server_replica_cert(self):
        # grab server certificate and make its replica
        server_cert = self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT), SSL_PROTO)
        ss_replica_cert_req = self.cert_factory.mk_replica_certreq_n_keys(server_cert)

        # check that CN is right
        self.assertEqual(
            TEST_SERVER_CN,
            ss_replica_cert_req[0].get_subject().CN)

        # load CA and sign the replica
        ca_certnkey = self.cert_factory.load_certnkey_files(TEST_USER_CA_CERT_FILE, TEST_USER_CA_KEY_FILE)
        ss_replica_certnkey = self.cert_factory.sign_cert_req(ss_replica_cert_req, ca_certnkey)

        # check that CN is still right
        self.assertEqual(
            server_cert.get_subject().as_text(),
            ss_replica_certnkey.cert.get_subject().as_text())

        # check issuer
        self.assertEqual(
            ca_certnkey.cert.get_subject().as_text(),
            ss_replica_certnkey.cert.get_issuer().as_text())

    def test__grab_server_x509_cert(self):
        server_cert = self.cert_factory.grab_server_x509_cert((TEST_SERVER_HOST, TEST_SERVER_PORT), SSL_PROTO)
        # check CN of server certificate
        self.assertEqual(server_cert.get_subject().CN, TEST_SERVER_CN)

if __name__ == '__main__':
    unittest.main()
