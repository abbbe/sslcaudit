''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
from src.CertFactory import CertFactory
from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.SSL.SSLClientConnectionAuditor import SSLClientConnectionAuditor

DEFAULT_CN = 'nonexistent.gremwell.com'
UNKNOWN_CA = 'tlsv1 alert unknown ca'
UNEXPECTED_EOF = 'unexpected eof'
CONNECTED = 'connected'

class SSLClientAuditorSet(ClientAuditorSet):
    def __init__(self, name, options):
        self.name = name
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
#        self.init_usercert()
        self.init_self_signed()
#        self.init_goodca_signed()

        ClientAuditorSet.__init__(self, self.auditors)

#    def init_usercert(self):
#        if self.options.cert_file != None:
#            # expected to fail with invalid CA error
#            certnkey = self.cert_factory.load_certnkey('huh', self.options.cert_file)
#            expect_failure = "CN mismatch"
#            auditor = SSLClientConnectionAuditor('usercert', 'zzz', self.proto, certnkey,
#                expect_failure=expect_failure)
#            self.auditors.append(auditor)

    def init_self_signed(self):
        '''
        This method initializes auditors using self-signed certificates
        '''
        if not self.options.no_self_signed:
            self._init_signed(ca_certnkey=None)

#    def init_usercert_signed(self):
#        '''
#        This method initializes auditors using certificates signed by user-specified cert
#        '''
#        if self.options.cert_file != None:
#            self._init_signed('usercert', cacert_file=self.options.cert_file, expect_trust=False)

    def init_goodca_signed(self):
        '''
        This method initializes auditors using certificates signed by known good CA
        '''
        if self.options.user_ca_certnkey != None:
            self._init_signed(ca_certnkey=self.options.user_ca_certnkey)

    def _init_signed(self, ca_certnkey):
        '''
        This method initializes auditors using signed certificates: self signed or by a CA.
        '''
        if not self.options.no_default_cn:
            self._init_signedtests(DEFAULT_CN, ca_certnkey)

        if self.options.cn != None:
            self._init_signedtests(self.options.cn, ca_certnkey)

    def _init_signedtests(self, cn, ca_certnkey):
        certnkey = self.cert_factory.new_certnkey(cn, ca_certnkey)
        auditor = SSLClientConnectionAuditor(self.proto, certnkey)
        self.auditors.append(auditor)

#            certnkey = self.cert_factory.new_certnkey('default_cn/selfsigned', self.options.cn, cacert_file)
#            if cacert_file != None and expect_trust:
#                ## assuming user has provided sensible CN, a certificate signed by a trusted CA expected to produce no error
#                expect_failure = None
#            else:
#                ## self signed certificates or ones signed by untrusted CA expected to produce CA error
#                expect_failure = UNKNOWN_CA
#            auditor = SSLClientConnectionAuditor(self.proto, certnkey, expect_failure=expect_failure)
#            self.auditors.append(auditor)
#
#        if self.server_cert != None:
#            # automatically generated certificate, replicated after a user-specified server cert, selfsigned
#            certnkey = self.cert_factory.new_certnkey(proto_cert=self.server_cert, cacert_file)
#            if cacert_file != None and expect_trust:
#                ## assuming user has pointed to a sensible server, a certificate signed by a trusted CA expected to produce no error
#                expect_failure = None
#            else:
#                ## self signed certificates or ones signed by untrusted CA expected to produce CA error
#                expect_failure = UNKNOWN_CA
#            auditor = SSLClientConnectionAuditor(self.proto, certnkey, expect_failure=expect_failure)
#            self.auditors.append(auditor)
#
