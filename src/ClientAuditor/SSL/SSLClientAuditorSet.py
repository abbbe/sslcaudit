from src.CertFactory import CertFactory
from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.SSL.SSLClientConnectionAuditor import SSLClientConnectionAuditor

DEFAULT_X509_SELFSIGNED_CERT_CN = "nonexistent.gremwell.com"

UNKNOWN_CA = "tlsv1 alert unknown ca"

class SSLClientAuditorSet(ClientAuditorSet):

    def __init__(self, options):
        self.options = options

        self.proto = 'sslv23'
        self.cert_factory = CertFactory()

        if self.options.server != None:
            # fetch a certificate from user-specified server
            # cache the certificate, may be reused later on
            self.server_cert = self.cert_factory.grab_server_cert(self.options.server)
        else:
            self.server_cert = None

        self.auditors = []
        self.init_self_signed()
        self.init_usercert_signed()
        self.init_goodca_signed()

        ClientAuditorSet.__init__(self, self.auditors)

    def init_self_signed(self):
        '''
        This method initializes auditors using self-signed certificates
        '''
        if not self.options.no_self_signed:
            self._init_signed(cacert_file=None, expect_trust=False)

    def init_usercert_signed(self):
        '''
        This method initializes auditors using certificates signed by user-specified cert
        '''
        if self.options.cert_file != None:
            self._init_signed(cacert_file=self.options.cert_file, expect_trust=False)

    def init_goodca_signed(self):
        '''
        This method initializes auditors using certificates signed by known good CA
        '''
        if self.options.good_cacert_file != None:
            self._init_signed(cacert_file=self.options.good_cacert_file, expect_trust=True)

    def _init_signed(self, cacert_file, expect_trust):
        '''
        This method initializes auditors using signed certificates: self signed or by a CA.
        '''
        if not self.options.no_default_cn:
            # automatically generated certificate, with default CN, selfsigned
            # expected to fail with invalid CA error
            certnkey = self.cert_factory.new_certnkey(cn = DEFAULT_X509_SELFSIGNED_CERT_CN, cacert_file=cacert_file)
            if cacert_file != None and expect_trust:
                ## certificate signed by a trusted CA expected to produce CN mismatch error
                expect_failure = "CN mismatch"
            else:
                ## self signed certificates or ones signed by untrusted CA expected to produce CA error
                expect_failure = UNKNOWN_CA
            auditor = SSLClientConnectionAuditor(self.proto, certnkey, expect_failure=expect_failure)
            self.auditors.append(auditor)

        if self.options.cn != None:
            # automatically generated certificate, with user-supplied CN, selfsigned
            # expected to fail with invalid CA error
            certnkey = self.cert_factory.new_certnkey(cn = self.options.cn, cacert_file=cacert_file)
            if cacert_file != None and expect_trust:
                ## assuming user has provided sensible CN, a certificate signed by a trusted CA expected to produce no error
                expect_failure = None
            else:
                ## self signed certificates or ones signed by untrusted CA expected to produce CA error
                expect_failure = UNKNOWN_CA
            auditor = SSLClientConnectionAuditor(self.proto, certnkey, expect_failure=expect_failure)
            self.auditors.append(auditor)

        if self.server_cert != None:
            # automatically generated certificate, replicated after a user-specified server cert, selfsigned
            certnkey = self.cert_factory.new_certnkey(proto_cert = self.server_cert, cacert_file=cacert_file)
            if cacert_file != None and expect_trust:
                ## assuming user has pointed to a sensible server, a certificate signed by a trusted CA expected to produce no error
                expect_failure = None
            else:
                ## self signed certificates or ones signed by untrusted CA expected to produce CA error
                expect_failure = UNKNOWN_CA
            auditor = SSLClientConnectionAuditor(self.proto, certnkey, expect_failure=expect_failure)
            self.auditors.append(auditor)
