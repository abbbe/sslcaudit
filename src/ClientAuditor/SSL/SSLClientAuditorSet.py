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

        self.proto = 'sslv23' # XXX
        self.cert_factory = CertFactory()

        # handle --server= option
        if self.options.server != None:
            # fetch X.509 certificate from user-specified server
            self.server_x509_cert = self.cert_factory.grab_server_x509_cert(self.options.server)
        else:
            self.server_x509_cert = None

        # handle --user-cert= and --user-key= options
        if (self.options.user_cert_file != None) and (self.options.user_key_file != None):
            try:
                self.user_certnkey = self.cert_factory.load_certnkey_files(
                    self.options.user_cert_file, self.options.user_key_file)
            except IOError as ex:
                raise IOError(ex)
        else:
            self.user_certnkey = None

        # handle --user-ca-cert= and --user-ca-key= options
        if (self.options.user_ca_cert_file != None) and (self.options.user_ca_key_file != None):
            try:
                self.user_ca_certnkey = self.cert_factory.load_certnkey_files(
                    self.options.user_ca_cert_file, self.options.user_ca_key_file)
            except IOError as ex:
                raise IOError(ex)
        else:
            self.user_ca_certnkey = None

        self.auditors = []

        self.init_user_cert()
        self.init_self_signed()
        self.init_userca_signed()

        ClientAuditorSet.__init__(self, self.auditors)

    def init_user_cert(self):
        if self.user_certnkey != None:
            # create an auditor using user-supplied certificate as is
            auditor = SSLClientConnectionAuditor(self.proto, self.user_certnkey)
            self.auditors.append(auditor)

            # create a set of auditors using user-supplied certificate as CA
            self._init_signed(ca_certnkey=self.user_certnkey)

    def init_self_signed(self):
        '''
        This method initializes auditors using self-signed certificates
        '''
        if not self.options.no_self_signed:
            self._init_signed(ca_certnkey=None)

    def init_userca_signed(self):
        '''
        This method initializes auditors using certificates signed by known good CA
        '''
        if self.user_ca_certnkey != None:
            self._init_signed(ca_certnkey=self.user_ca_certnkey)

    def _init_signed(self, ca_certnkey):
        '''
        This method initializes auditors using signed certificates: self signed or by a CA.
        '''
        if not self.options.no_default_cn:
            self._init_signedtests(DEFAULT_CN, ca_certnkey)

        if self.options.user_cn != None:
            self._init_signedtests(self.options.user_cn, ca_certnkey)

        if self.server_x509_cert != None:
            # automatically generated certificate, replicated after a user-specified server cert, selfsigned
            if ca_certnkey == None:
                certnkey = self.cert_factory.mk_selfsigned_replica_certnkey(self.server_x509_cert)
            else:
                raise NotImplemented()

            auditor = SSLClientConnectionAuditor(self.proto, certnkey)
            self.auditors.append(auditor)

    def _init_signedtests(self, cn, ca_certnkey):
        certnkey = self.cert_factory.new_certnkey(cn, ca_certnkey)
        auditor = SSLClientConnectionAuditor(self.proto, certnkey)
        self.auditors.append(auditor)

