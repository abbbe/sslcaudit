''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
from M2Crypto import X509

from src.core.ConfigErrorException import ConfigErrorException
from src.core.CertFactory import CertFactory
from src.modules.base.BaseProfileFactory import BaseProfileFactory, BaseProfile, BaseProfileSpec
from src.modules.sslcert.SSLServerHandler import SSLServerHandler

DEFAULT_CN = 'nonexistent.gremwell.com'
IM_CA_NONE_CN = 'ca-none'
IM_CA_FALSE_CN = 'ca-false'
IM_CA_TRUE_CN = 'ca-true'

sslcert_server_handler = SSLServerHandler('sslv23')

class SSLProfileSpec_SelfSigned(BaseProfileSpec):
    def __init__(self, cn):
        self.cn = cn

    def __str__(self):
        return "selfsigned(%s)" % self.cn

class SSLProfileSpec_Signed(BaseProfileSpec):
    def __init__(self, cn, ca_cn):
        self.cn = cn
        self.ca_cn = ca_cn

    def __str__(self):
        return "signed1(%s, %s)" % (self.cn, self.ca_cn)

class SSLProfileSpec_IMCA_Signed(BaseProfileSpec):
    def __init__(self, cn, im_ca_cn, ca_cn):
        self.cn = cn
        self.im_ca_cn = im_ca_cn
        self.ca_cn = ca_cn

    def __str__(self):
        return "signed2(%s, %s, %s)" % (self.cn, self.im_ca_cn, self.ca_cn)

class SSLServerCertProfile(BaseProfile):
    def __init__(self, profile_spec, certnkey):
        self.profile_spec = profile_spec
        self.certnkey = certnkey

    def get_spec(self):
        return self.profile_spec

    def get_handler(self):
        return sslcert_server_handler

    def __str__(self):
        return str(self.profile_spec)

class ProfileFactory(BaseProfileFactory):
    def __init__(self, file_bag, options, protocol='sslv23'):
        BaseProfileFactory.__init__(self, file_bag, options)

        self.protocol = protocol
        self.cert_factory = CertFactory(self.file_bag)

        self.init_options()

#        self.init_user_cert()
        self.init_cert_requests()
        self.add_user_cert_profile()
        self.add_profiles()

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

    # ----------------------------------------------------------------------------------------------

    def init_cert_requests(self):
        self.certreq_n_keyss = []

        if not self.options.no_default_cn:
            req1 = self.cert_factory.mk_certreq_n_keys(cn=DEFAULT_CN)
            self.certreq_n_keyss.append(req1)

        if self.options.user_cn != None:
            req2 = self.cert_factory.mk_certreq_n_keys(cn=self.options.user_cn)
            self.certreq_n_keyss.append(req2)

#        if self.options.server != None:
#            cert_req3 = self.cert_factory.mk_cert_request_replicating_server(server=self.options.server)
#            self.cert_requests.append(cert_req3)

    def add_user_cert_profile(self):
        '''
        This method initializes an auditor using user-supplied certificate as is
        '''
        if self.user_certnkey != None:
            self.add_profile(SSLServerCertProfile(self.user_certnkey))

    def add_profiles(self):
        if not self.options.no_self_signed:
            self.add_signed_profiles(ca_certnkey=None)

        if self.user_certnkey != None:
            self.add_signed_profiles(ca_certnkey=self.user_certnkey)

        if self.user_ca_certnkey != None:
            self.add_signed_profiles(ca_certnkey=self.user_ca_certnkey)
            self.add_im_basic_constraints_profiles()

    def add_im_basic_constraints_profiles(self):
        '''
        This method initializes auditors testing for basicConstraints violations
        '''

        for cert_req in self.certreq_n_keyss:
            self.add_im_basic_constraints_profile(cert_req, basicConstraint_CA=None)
            self.add_im_basic_constraints_profile(cert_req, basicConstraint_CA=False)
            self.add_im_basic_constraints_profile(cert_req, basicConstraint_CA=True)

            # XXX if no user-cn and defalt-cn is disabled the test will not be performed silently

    # ----------------------------------------------------------------------------------------------

    def add_signed_profiles(self, ca_certnkey):
        for certreq_n_keys in self.certreq_n_keyss:
            cn = certreq_n_keys[0].get_subject().CN
            if ca_certnkey == None:
                cert_spec = SSLProfileSpec_SelfSigned(cn)
            else:
                ca_cn = ca_certnkey.cert.get_subject().CN
                cert_spec = SSLProfileSpec_Signed(cn, ca_cn)

            self.add_signed_profile(cert_spec, certreq_n_keys, ca_certnkey)

    def add_signed_profile(self, cert_spec, certreq_n_keys, ca_certnkey):
        certnkey = self.cert_factory.sign_cert_req(certreq_n_keys=certreq_n_keys, ca_certnkey=ca_certnkey)
        self.add_profile(SSLServerCertProfile(cert_spec, certnkey))

    def add_im_basic_constraints_profile(self, cert_req, basicConstraint_CA=None):
        # create an intermediate authority, signed by user-supplied CA, possibly with proper constraints
        if basicConstraint_CA != None:
            if basicConstraint_CA:
                ext_value="CA:TRUE"
                im_ca_cn = IM_CA_TRUE_CN
            else:
                ext_value = "CA:FALSE"
                im_ca_cn = IM_CA_FALSE_CN
            ca_ext = X509.new_extension("basicConstraints", ext_value)
            ca_ext.set_critical()
            v3_exts=[ca_ext]
        else:
            v3_exts=[]
            im_ca_cn = IM_CA_NONE_CN

        # create the intermediate CA
        im_ca_cert_req = self.cert_factory.mk_certreq_n_keys(cn=im_ca_cn, v3_exts=v3_exts)
        im_ca_certnkey = self.cert_factory.sign_cert_req(im_ca_cert_req, ca_certnkey=self.user_ca_certnkey)

        # create server certificate, signed by that authority
        certnkey = self.cert_factory.sign_cert_req(cert_req, ca_certnkey=im_ca_certnkey)

        # create auditor using that certificate
        cn = certnkey.cert.get_subject().CN
        ca_cn = self.user_ca_certnkey.cert.get_subject().CN
        spec = SSLProfileSpec_IMCA_Signed(cn, im_ca_cn, ca_cn)
        self.add_profile(SSLServerCertProfile(spec, certnkey))

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
            return self.cert_factory.load_certnkey_files(cert_file, key_file)
        except IOError as ex:
            raise ConfigErrorException(ex)
