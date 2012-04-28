''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import socket

from tempfile import NamedTemporaryFile
from M2Crypto import X509, ASN1, RSA, EVP, util, SSL
import time

DEFAULT_X509_CN = "nonexistent.gremwell.com"
DEFAULT_X509_C = "BE"
DEFAULT_X509_O = "Gremwell bvba"

class CertAndKey(object):
    '''
    This class holds:
     * object name
     * X509 certificate object
     * path to the cert file
     * path to the key file
    '''

    def __init__(self, name, cert, cert_filename, key_filename):
        self.name = name
        self.cert = cert
        self.cert_filename = cert_filename
        self.key_filename = key_filename

    def __repr__(self):
        return "CertAndKey%s" % self.__dict__

    def __str__(self):
        return str(self.name)


class CertFactory(object):
    def new_certnkey(self, cn, ca_certnkey):
        if ca_certnkey != None:
            raise NotImplemented() # XXX really need to implement this one
        else:
            return self.mk_simple_selfsigned_certnkey(cn, DEFAULT_X509_C, DEFAULT_X509_O)

    def mk_simple_selfsigned_certnkey(self, cn, country, org):
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

        return self._mk_selfsigned_certnkey(2, 1, not_before, not_after, subj, 1024, exts)

    def _mk_selfsigned_certnkey(self, version, serial_number, not_before, not_after, subj, bits, exts):
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

        # XXX arrange for evidence preservation

        return CertAndKey((subj.CN, 'SELF'), cert, cert_file.name, key_file.name)

    def mk_selfsigned_replica_certnkey(self, orig_cert):
        '''
        This function creates a self-signed replica of the given certificate. It returns a tuple of certificate and
        Most of the fields of the original certificates are replicated:
         * key length
         * subject
         * validity dates
         * serial number
         * version
         * extensions
        Couple parameters don't get replicated (because I don't know where to find them in M2Crypto.X509 object):
         * public key exponent which is fixed to 65537,
         * signature algorithm which is fixed to sha1WithRSAEncryption.
        '''
        public_key = orig_cert.get_pubkey()
        bits = public_key.get_rsa().__len__()
        subj = orig_cert.get_subject()
        not_after = orig_cert.get_not_after()
        not_before = orig_cert.get_not_before()
        serial_number = orig_cert.get_serial_number()
        version = orig_cert.get_version()
        exts = []
        for i in range(orig_cert.get_ext_count()):
            exts.append(orig_cert.get_ext_at(i))

        return self._mk_selfsigned_certnkey(version, serial_number, not_before, not_after, subj, bits, exts)

    def grab_server_x509_cert(self, server):
        '''
        This function connects to the specified server and grabs its certificate.
        Expects (server, port) tuple as input.
        '''
        # create context
        ctx = SSL.Context() # XXX should we try different protocols here
        ctx.set_allow_unknown_ca(True)
        ctx.set_verify(SSL.verify_none, 0)

        # socket
        sock = socket.create_connection(server)

        # establish connection
        sslsock = SSL.Connection(ctx, sock=sock)
        sslsock.set_post_connection_check_callback(None)
        sslsock.setup_ssl()
        sslsock.set_connect_state()
        sslsock.connect_ssl()

        # grab server certificate and shut the connection
        server_cert = sslsock.get_peer_cert()
        sslsock.close()

        return server_cert

    #    def grab_server_x509_cert(self, host, port):
    #        '''
    #        This is another way to do the same
    #        '''
    #        import ssl
    #        cert_pem = ssl.get_server_certificate((host, port))
    #        return X509.load_cert_string(cert_pem, X509.FORMAT_PEM)
    #

    def load_certnkey_files(self, cert_file, key_file):
        '''
        This function loads the content of the certificate file
        and initalizes pathes to the certificate and the key.
	    '''
        x509_cert = X509.load_cert(cert_file)
        return CertAndKey(x509_cert.get_subject().CN, x509_cert, cert_file, key_file)
