''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
import unittest
import M2Crypto
from src import CertUtils
from src.CertUtils import mk_simple_selfsigned_certnkey, CertAndKey

TEST_HOST = 'imap.gmail.com'
TEST_PORT = 993

class TestCertUtils(unittest.TestCase):
    def test_mk_simple_selfsigned_cert(self):
        certnkey = CertUtils.mk_simple_selfsigned_certnkey()
        good_subj = 'CN=%s, C=%s, O=%s' % (CertUtils.DEFAULT_X509_CN, CertUtils.DEFAULT_X509_C, CertUtils.DEFAULT_X509_O)
        self.assertEqual(good_subj, certnkey.cert.get_subject().as_text(), )

    def test_mk_selfsigned_replica_cert(self):
        server_cert = CertUtils.grab_server_cert(TEST_HOST, TEST_PORT)
        ss_replica_certnkey = CertUtils.mk_selfsigned_replica_certnkey(server_cert)
        self.assertEqual(server_cert.get_subject().as_text(), ss_replica_certnkey.cert.get_subject().as_text())

    def test_write_tempfiles(self):
        mk_simple_selfsigned_certnkey()
