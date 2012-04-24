import unittest

from src.CertUtils import grab_server_cert, mk_selfsigned_replica_cert, mk_simple_selfsigned_cert

TEST_HOST = 'imap.gmail.com'
TEST_PORT = 993

class TestCertUtils(unittest.TestCase):
    def test__mk_simple_selfsigned_cert(self):
        ss_cert = mk_simple_selfsigned_cert()
        self.assertEqual(ss_cert.get_subject().as_text(), 'CN=nonexistent.gremwell.com, C=BE, O=Gremwell bvba')

    def test__mk_selfsigned_replica_cert(self):
        server_cert = grab_server_cert(TEST_HOST, TEST_PORT)
        ss_replica_cert = mk_selfsigned_replica_cert(server_cert)
        self.assertEqual(server_cert.get_subject().as_text(), ss_replica_cert.get_subject().as_text())
