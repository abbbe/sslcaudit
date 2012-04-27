from tempfile import NamedTemporaryFile
from M2Crypto import X509, ASN1, RSA, EVP, util
import time

DEFAULT_X509_CN = "nonexistent.gremwell.com"
DEFAULT_X509_C = "BE"
DEFAULT_X509_O = "Gremwell bvba"

class CertAndKey(object):
    def __init__(self, name, cert, cert_filename, key_filename):
        self.name = name
        self.cert = cert
        self.cert_filename = cert_filename
        self.key_filename = key_filename

    def __str__(self):
        return name

class CertFactory(object):
    def grab_server_cert(self, server):
        raise NotImplemented()

    def new_certnkey(self, name, cn, cacert_file):
        if cacert_file != None:
            raise NotImplemented()
        else:
            return self.mk_simple_selfsigned_certnkey(name, cn, DEFAULT_X509_C, DEFAULT_X509_O)

    def mk_simple_selfsigned_certnkey(self, name, cn, country, org):
        '''
        This function creates a self-signed server certificate with:
         * default common name, organization, and country
         * maximum validity period
        It returns the certificate and the keypair.
        '''
        subj = X509.X509_Name()
        subj.CN = cn
        subj.C = country
        subj.O = org

        # maximum possible validity time frame
        now = long(time.time())
        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(0)
        not_after = ASN1.ASN1_UTCTIME()
        not_after.set_time(2 ** 31)

        # build a list of extensions
        #X509v3 Basic Constraints: CA:FALSE
        exts = []
        #ext = X509.new_extension('basicConstraints', 'CA:FALSE')
        #ext.set_critical(1)
        #exts.append(ext)
        #Netscape Cert Type:
        #SSL Server
        #ext = X509.new_extension('nsCertType', 'SSL Server')
        #exts.append(ext)

        return self._mk_selfsigned_certnkey(name, 2, 1, not_before, not_after, subj, 1024, exts)

    def _mk_selfsigned_certnkey(self, name, version, serial_number, not_before, not_after, subj, bits, exts):
        '''
        This function generates a self signed certificate with given attributes.
        It returns the certificate and the private key. Normally used internally only.
        '''

        exp = 65537 # hardcoded
        hash = 'sha1' # XXX unused?

        # create a new keypair
        rsa_keypair = RSA.gen_key(bits, exp, util.no_passphrase_callback)
        public_key = EVP.PKey()
        public_key.assign_rsa(rsa_keypair)

        # create self-signed certificate
        cert = X509.X509()
        cert.set_serial_number(serial_number)
        cert.set_version(version)
        cert.set_subject(subj)
        cert.set_issuer(subj)
        cert.set_pubkey(public_key)
        cert.set_not_before(not_before)
        cert.set_not_after(not_after)
        for ext in exts: cert.add_ext(ext)

        # sign
        cert.sign(public_key, hash)

        cert_file = NamedTemporaryFile(delete=False)
        cert_file.write(cert.as_text())
        cert_file.write(cert.as_pem())
        cert_file.close()

        key_file = NamedTemporaryFile(delete=False)
        rsa_keypair.save_key(key_file.name, None)
        key_file.close()

        # XXX arrange for temporary files removal

        return CertAndKey(name, cert, cert_file.name, key_file.name)
