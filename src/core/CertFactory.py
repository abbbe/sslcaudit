''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import socket

from M2Crypto import X509, ASN1, RSA, EVP, util, SSL
import M2Crypto
from M2Crypto.SSL import SSLError
from src.core.ConfigError import ConfigError

DEFAULT_X509_C = 'BE'
DEFAULT_X509_ORG = 'Gremwell bvba'
SELFSIGNED = 'SELF'
BITS=1024

CERT_FILE_SUFFIX = '-cert.pem'
KEY_FILE_SUFFIX = '-key.pem'

class CertAndKey(object):
    '''
    This class holds:
     * object name
     * X509 certificate object
     * path to the cert file
     * path to the key file
    '''

    def __init__(self, name, cert_filename, key_filename, cert, pkey):
        self.name = name
        self.cert = cert
        self.cert_filename = cert_filename
        self.key_filename = key_filename

        if cert == None:
            self.cert = X509.load_cert(self.cert_filename)
        else:
            self.cert = cert

        if pkey == None:
            self.pkey = EVP.load_key(self.key_filename)
        else:
            self.pkey = pkey

    def __repr__(self):
        return "CertAndKey%s" % self.__dict__

    def __str__(self):
        return str(self.name)


DEFAULT_BITS = 1024

class CertFactory(object):
    '''
    This class provides methods to generate new X509 certificates and corresponding
    keys, encapsulated into CertAndKey objects.
    '''

    def __init__(self, file_bag):
        self.file_bag = file_bag

    def load_certnkey_files(self, cert_file, key_file):
        '''
        This function loads the content of the certificate file
        and initializes paths to the certificate and the key.
	    '''
        try:
            cert = X509.load_cert(cert_file)
        except M2Crypto.X509.X509Error as ex:
            raise ConfigError('failed to parse cert file %s, exception: %s' % (cert_file, ex))

        try:
            pkey = EVP.load_key(key_file)
        except M2Crypto.EVP.EVPError as ex:
            raise ConfigError('failed to parse key file %s, exception: %s' % (key_file, ex))

        return CertAndKey(cert.get_subject().CN, cert_file, key_file, cert, pkey)

    def mk_certreq_n_keys(self, cn, v3_exts=[]):
        '''
        This function creates a certificate request with following attributes:
         * given common name, organization, and country
         * maximum validity period
         * given extensions
        Returns the certificate request and the keys as a tuple (X509, EVP, RSA)
        '''
        bits = DEFAULT_BITS

        # subject
        subj = X509.X509_Name()
        subj.CN = cn
        subj.C = DEFAULT_X509_C
        subj.O = DEFAULT_X509_ORG

        # maximum possible validity time frame
        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(0)
        not_after = ASN1.ASN1_UTCTIME()
        not_after.set_time(2 ** 31 - 1)

        return self.dododo(bits, subj, not_before, not_after, v3_exts)

    def dododo(self, bits, subj, not_before, not_after, v3_exts, version=3):
        # create a new keypair
        rsa_keypair = RSA.gen_key(bits, 65537, util.no_passphrase_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa_keypair, capture=False)

        # create certificate request
        cert_req = X509.X509()
        cert_req.set_version(version)
        cert_req.set_subject(subj)
        cert_req.set_pubkey(pkey)
        cert_req.set_not_before(not_before)
        cert_req.set_not_after(not_after)

        for ext in v3_exts:
            cert_req.add_ext(ext)

        return (cert_req, pkey, rsa_keypair)

    def sign_cert_req(self, certreq_n_keys, ca_certnkey):
        '''
        This function signs the certificate request.
        Expects a tuple (X509, EVP, RSA) as returned by mk_certreq_n_keys().
        Returns CertAndKey() object.
        '''
        (cert_req, pkey, rsa_keypair) = certreq_n_keys

        # hardcoded parameters
        md = 'sha1'

        # XXX
        cert_req.set_serial_number(1)

        # set issuer
        if ca_certnkey != None:
            cert_req.set_issuer(ca_certnkey.cert.get_subject())
        else:
            cert_req.set_issuer(cert_req.get_subject())

        # sign
        if ca_certnkey != None:
            cert_req.sign(ca_certnkey.pkey, md)
            signed_by = ca_certnkey.name
        else:
            cert_req.sign(pkey, md)
            signed_by = SELFSIGNED

        # save the certificate in a file
        (cert_file, key_file) = self.file_bag.mk_two_files(suffix1=CERT_FILE_SUFFIX, suffix2=KEY_FILE_SUFFIX)
        cert_file.write(cert_req.as_text())
        cert_file.write(cert_req.as_pem())
        if ca_certnkey != None:
            cert_file.write(ca_certnkey.cert.as_text())
            cert_file.write(ca_certnkey.cert.as_pem())
        cert_file.close()

        # save the private key in a file
        rsa_keypair.save_key(key_file.name, None)
        key_file.close()

        return CertAndKey((cert_req.get_subject().CN, signed_by), cert_file.name, key_file.name, cert_req, pkey)

    def grab_server_x509_cert(self, server, protocol):
        '''
        This function connects to the specified server and grabs its certificate.
        Expects (server, port) tuple as input.
        '''
        # create context
        ctx = SSL.Context(protocol=protocol)
        ctx.set_allow_unknown_ca(True)
        ctx.set_verify(SSL.verify_none, 0)

        # establish TCP connection to the server
        sock = socket.create_connection(server)

        # prepare SSL context
        sslsock = SSL.Connection(ctx, sock=sock)
        sslsock.set_post_connection_check_callback(None)
        sslsock.setup_ssl()
        sslsock.set_connect_state()

        # try to establish SSL connection
        try:
            sslsock.connect_ssl()
            ssl_connect_ex = None
        except SSLError as ex:
            # this exception is not necessarily a deal breaker
            # save it until we check if server certificate is available
            ssl_connect_ex = ex

        # grab server certificate and shut the connection
        server_cert = sslsock.get_peer_cert()
        sslsock.close()

        if server_cert is None:
            # failed to grab the certificate, rethrow the exception
            raise ssl_connect_ex

        return server_cert

    def mk_replica_certreq_n_keys(self, orig_cert):
        '''
        This function creates a certificate request replicating given certificate. It returns a tuple of certificate and
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

        # copy certificate attributes
        public_key = orig_cert.get_pubkey()

        bits = public_key.get_rsa().__len__()
        subj = orig_cert.get_subject()
        not_before = orig_cert.get_not_before()
        not_after = orig_cert.get_not_after()
        version = orig_cert.get_version()

        v3_exts = []
        for i in range(orig_cert.get_ext_count()):
            v3_exts.append(orig_cert.get_ext_at(i))

        return self.dododo(bits, subj, not_before, not_after, v3_exts, version)
