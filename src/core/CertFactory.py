''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

# see https://bugzilla.osafoundation.org/show_bug.cgi?id=13053

import socket

from tempfile import NamedTemporaryFile
from M2Crypto import X509, ASN1, RSA, EVP, util, SSL

DEFAULT_X509_C = 'BE'
DEFAULT_X509_ORG = 'Gremwell bvba'

SELFSIGNED = 'SELF'

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

    def new_certnkey(self, cn, country=DEFAULT_X509_C, org=DEFAULT_X509_ORG, ca_certnkey=None, v3_ext=[]):
        '''
        It generates a new certificate with given CN. If CA specified,
        it signs the new certificate by given CA. Otherwise, it self-signs it.
        '''
        if ca_certnkey != None:
            return self._mk_simple_signed_certnkey(cn, country, org, ca_certnkey, v3_ext)
        else:
            return self._mk_simple_selfsigned_certnkey(cn, DEFAULT_X509_C, DEFAULT_X509_ORG, v3_ext)

    def _mk_simple_selfsigned_certnkey(self, cn, country, org, v3_ext):
        '''
        This function creates a self-signed server certificate with following attributes:
         * given common name, organization, and country
         * maximum validity period
        Returns CertAndKey object.
        '''
        subj = X509.X509_Name()
        subj.CN = cn
        subj.C = country
        subj.O = org

        # maximum possible validity time frame
        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(0)
        not_after = ASN1.ASN1_UTCTIME()
        not_after.set_time(2 ** 31 - 1)

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

        return self._mk_signed_certnkey(2, 1, not_before, not_after, subj, 1024, v3_ext)

    def _mk_simple_signed_certnkey(self, cn, country, org, ca_certnkey, v3_ext):
        '''
        This function creates a signed certificate with following attributes:
         * given common name, organization, and country
         * maximum validity period
        Returns CertAndKey object.
        '''
        subj = X509.X509_Name()
        subj.CN = cn
        subj.C = country
        subj.O = org

        # maximum possible validity time frame
        not_before = ASN1.ASN1_UTCTIME()
        not_before.set_time(0)
        not_after = ASN1.ASN1_UTCTIME()
        not_after.set_time(2 ** 31)

        return self._mk_signed_certnkey(2, 1, not_before, not_after, subj, 1024, v3_ext, ca_certnkey)

    def mk_signed_replica_certnkey(self, orig_cert, ca_certnkey=None):
        '''
        This function creates a signed or self-signed replica of the given certificate. It returns a tuple of certificate and
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
        not_after = orig_cert.get_not_after()
        not_before = orig_cert.get_not_before()
        serial_number = orig_cert.get_serial_number()
        version = orig_cert.get_version()

        # copy extensions
        exts = []
        for i in range(orig_cert.get_ext_count()):
            exts.append(orig_cert.get_ext_at(i))

        return self._mk_signed_certnkey(version, serial_number, not_before, not_after, subj, bits, exts, ca_certnkey)

    def _mk_signed_certnkey(self, version, serial_number, not_before, not_after, subj, bits, exts, ca_certnkey=None):
        '''
        This function generates a self signed certificate with given attributes.
        It returns the certificate and the private key. Normally used internally only.
        '''

        exp = 65537 # hardcoded
        md = 'sha1'

        # create a new keypair
        rsa_keypair = RSA.gen_key(bits, exp, util.no_passphrase_callback)
        pkey = EVP.PKey()
        pkey.assign_rsa(rsa_keypair, capture=False)

        # create self-signed certificate
        cert = X509.X509()
        cert.set_serial_number(serial_number)
        cert.set_version(version)
        cert.set_subject(subj)
        if ca_certnkey == None:
            cert.set_issuer(subj)
        else:
            cert.set_issuer(ca_certnkey.cert.get_subject())
        cert.set_pubkey(pkey)
        cert.set_not_before(not_before)
        cert.set_not_after(not_after)
        for ext in exts: cert.add_ext(ext)

        # sign
        if ca_certnkey != None:
            cert.sign(ca_certnkey.pkey, md)
            signedby = ca_certnkey.name
        else:
            cert.sign(pkey, md)
            signedby = SELFSIGNED

        # save the certificate in a file
        cert_file = NamedTemporaryFile(delete=False)
        cert_file.write(cert.as_text())
        cert_file.write(cert.as_pem())
        if ca_certnkey != None:
            cert_file.write(ca_certnkey.cert.as_text())
            cert_file.write(ca_certnkey.cert.as_pem())
        cert_file.close()

        # save the private key in a file
        key_file = NamedTemporaryFile(delete=False)
        rsa_keypair.save_key(key_file.name, None)
        key_file.close()

        return CertAndKey((subj.CN, signedby), cert_file.name, key_file.name, cert, pkey)

    def grab_server_x509_cert(self, server, protocol='sslv23'):
        '''
        This function connects to the specified server and grabs its certificate.
        Expects (server, port) tuple as input. Gets optional proto parameter to explicitly
        specify the protocol.
        '''
        # create context
        ctx = SSL.Context(protocol=protocol)
        ctx.set_allow_unknown_ca(True)
        ctx.set_verify(SSL.verify_none, 0)

        # socket
        if isinstance(server, basestring):
            # not a tuple, expect HOST:PORT formatted string
            (host, port) = server.split(':')
            server = (host, int(port))

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

    def load_certnkey_files(self, cert_file, key_file):
        '''
        This function loads the content of the certificate file
        and initalizes pathes to the certificate and the key.
	    '''
        cert = X509.load_cert(cert_file)
        pkey = EVP.load_key(key_file)
        return CertAndKey(cert.get_subject().CN, cert_file, key_file, cert, pkey)

