''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import socket

from M2Crypto import X509, ASN1, RSA, EVP, util, SSL

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
        cert = X509.load_cert(cert_file)
        pkey = EVP.load_key(key_file)
        return CertAndKey(cert.get_subject().CN, cert_file, key_file, cert, pkey)

    def mk_certreq_n_keys(self, cn, v3_exts=[]):
        '''
        This function creates a certificate request with following attributes:
         * given common name, organization, and country
         * maximum validity period
         * given extensions
        Returns the certificate request and the keys as a tuple (X509, EVP, RSA)
        '''
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

        # create a new keypair
        rsa_keypair = RSA.gen_key(BITS, 65537, util.no_passphrase_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa_keypair, capture=False)

        # create certificate request
        cert_req = X509.X509()
        cert_req.set_version(3)
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
            cert_req.set_issuer(cert_req.get_issuer())

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

    def mk_cert_request_replicating_server(self, server):
        raise NotImplemented()