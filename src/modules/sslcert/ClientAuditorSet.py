''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
from M2Crypto import X509

from src.core.ConfigErrorException import ConfigErrorException
from src.core.CertFactory import CertFactory
from src.modules.base.BaseClientAuditorSet import BaseClientAuditorSet
from src.modules.sslcert.SSLClientConnectionAuditor import SSLClientConnectionAuditor

DEFAULT_CN = 'nonexistent.gremwell.com'
IM_NONCA_CN = 'without-ca-v3-ext'
IM_CA_CN = 'with-ca-v3-ext'

class ClientAuditorSet(BaseClientAuditorSet):
    def __init__(self, file_bag, options, protocol='sslv23'):
        BaseClientAuditorSet.__init__(self, file_bag, options)

        self.protocol = protocol
        self.cert_factory = CertFactory(self.file_bag)

        self.init_options()

        self.init_user_cert()
        self.init_self_signed()
        self.init_user_cert_signed()
        self.init_user_ca_signed()
        self.init_bad_constraints()
        self.init_expired()

    def init_options(self):
        # handle --server= option
        if self.options.server != None:
            # fetch X.509 certificate from user-specified server
            self.server_x509_cert = self.cert_factory.grab_server_x509_cert(self.options.server, protocol=self.protocol)
        else:
            self.server_x509_cert = None

        # handle --user-cert and --user-key options
        self.user_certnkey = self.load_certnkey(
            '--user-cert', self.options.user_cert_file,
            '--user-key', self.options.user_key_file)

        # handle --user-ca-cert and --user-ca-key options
        self.user_ca_certnkey = self.load_certnkey(
            '--user-ca-cert', self.options.user_ca_cert_file,
            '--user-ca-key', self.options.user_ca_key_file)

    def init_user_cert(self):
        '''
        This method initializes an auditor using user-supplied certificate as is
        '''
        if self.user_certnkey != None:
            auditor = SSLClientConnectionAuditor(self.protocol, self.user_certnkey)
            self.auditors.append(auditor)

    def init_self_signed(self):
        '''
        This method initializes auditors using self-signed certificates
        '''
        if not self.options.no_self_signed:
            self._init_signed(ca_certnkey=None)

    def init_user_cert_signed(self):
        '''
        This method initializes auditors using user-supplied certificate as CA
        '''
        if self.user_certnkey != None:
            self._init_signed(ca_certnkey=self.user_certnkey)

    def init_user_ca_signed(self):
        '''
        This method initializes auditors using certificates signed by known good CA
        '''
        if self.user_ca_certnkey != None:
            self._init_signed(ca_certnkey=self.user_ca_certnkey)

    def init_bad_constraints(self):
        '''
        This method initializes auditors testing for basicConstraints violations
        '''
        if self.user_ca_certnkey == None: return

        def _init_with_constraints(cn):
            self.init_with_constraints(cn, im_ca=None)
            self.init_with_constraints(cn, im_ca=False)
            self.init_with_constraints(cn, im_ca=True)

        if not self.options.no_default_cn:
            _init_with_constraints(DEFAULT_CN)

        if self.options.user_cn != None:
            _init_with_constraints(self.options.user_cn)

        # XXX if no user-cn and defalt-cn is disabled the test will not be performed silently

    def init_with_constraints(self, cn, im_ca=None):
        # create an intermediate authority, signed by user-supplied CA, possibly with proper constraints
        if im_ca:
            ca_ext = X509.new_extension("basicConstraints", "CA:TRUE")
            ca_ext.set_critical()
            v3_ext=[ca_ext]
        else:
            v3_ext=[]

        # create the intermediate CA
        im_ca_certnkey = self.cert_factory.new_certnkey(IM_NONCA_CN, ca_certnkey=self.user_ca_certnkey, v3_ext=v3_ext)

        # create server certificate, signed by that authority
        certnkey = self.cert_factory.new_certnkey(cn, ca_certnkey=im_ca_certnkey)

        # create auditor using that certificate
        auditor = SSLClientConnectionAuditor(self.protocol, certnkey)
        self.auditors.append(auditor)

    def init_expired(self):
        '''
        This method initializes auditors testing for expiration violations
        '''

        # create test certificate signed by user-supplied CA, but make it expired
        pass

    def _init_signed(self, ca_certnkey):
        '''
        This method initializes auditors using signed certificates: self signed or by a CA.
        '''
        if not self.options.no_default_cn:
            self._init_signedtests(DEFAULT_CN, ca_certnkey)

        if self.options.user_cn != None:
            self._init_signedtests(self.options.user_cn, ca_certnkey)

        if self.server_x509_cert != None:
            # automatically generated certificate, replicated after server cert, selfsigned
            if ca_certnkey == None:
                certnkey = self.cert_factory.mk_signed_replica_certnkey(self.server_x509_cert)
            else:
                certnkey = self.cert_factory.mk_signed_replica_certnkey(self.server_x509_cert, ca_certnkey)

            auditor = SSLClientConnectionAuditor(self.protocol, certnkey)
            self.auditors.append(auditor)

    def _init_signedtests(self, cn, ca_certnkey):
        certnkey = self.cert_factory.new_certnkey(cn, ca_certnkey=ca_certnkey)
        auditor = SSLClientConnectionAuditor(self.protocol, certnkey)
        self.auditors.append(auditor)

    def load_certnkey(self, cert_param, cert_file, key_param, key_file):
        '''
        This function loads X509 certificate from files and returns CertAndKey object.
        It throws a sensible ConfigErrorException in case of parameter error or problems
        with the input files.
        '''
        if (cert_file == None) and (key_file == None):
            return None

        if key_file == None:
            raise ConfigErrorException("If %s is set, %s must be set too" % (cert_param, key_param))

        if cert_file == None:
            raise ConfigErrorException("If %s is set, %s must be set too" % (key_param, cert_param))

        try:
            return self.cert_factory.load_certnkey_files(
                cert_file, key_file)
        except IOError as ex:
            raise ConfigErrorException(ex)
