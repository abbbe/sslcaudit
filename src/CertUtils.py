''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automatingsecurity audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
#from tempfile import NamedTemporaryFile
#import  time
#from M2Crypto import X509, ASN1, EVP, RSA, SSL, util
#
#DEFAULT_X509_CN = "nonexistent.gremwell.com"
#DEFAULT_X509_C = "BE"
#DEFAULT_X509_O = "Gremwell bvba"
#
#class CertAndKey(object):
#    def __init__(self, cert, cert_filename, key_filename):
#        self.cert = cert
#        self.cert_filename = cert_filename
#        self.key_filename = key_filename
#
#def mk_selfsigned_certnkey(version, serial_number, not_before, not_after, subj, bits, exts):
#    '''
#    This function generates a self signed certificate with given attributes.
#    It returns the certificate and the private key. Normally used internally only.
#    '''
#
#    exp = 65537 # hardcoded
#    hash = 'sha1' # XXX unused?
#
#    # create a new keypair
#    rsa_keypair = RSA.gen_key(bits, exp, util.no_passphrase_callback)
#    public_key = EVP.PKey()
#    public_key.assign_rsa(rsa_keypair)
#
#    # create self-signed certificate
#    cert = X509.X509()
#    cert.set_serial_number(serial_number)
#    cert.set_version(version)
#    cert.set_subject(subj)
#    cert.set_issuer(subj)
#    cert.set_pubkey(public_key)
#    cert.set_not_before(not_before)
#    cert.set_not_after(not_after)
#    for ext in exts: cert.add_ext(ext)
#
#    # sign
#    cert.sign(public_key, hash)
#
#    cert_file = NamedTemporaryFile(delete=False)
#    cert_file.write(cert.as_text())
#    cert_file.write(cert.as_pem())
#    cert_file.close()
#
#    key_file = NamedTemporaryFile(delete=False)
#    rsa_keypair.save_key(key_file.name, None)
#    key_file.close()
#
#    return CertAndKey(cert, cert_file.name, key_file.name)
#
#def mk_simple_selfsigned_certnkey(cn = DEFAULT_X509_CN, country = DEFAULT_X509_C, org = DEFAULT_X509_O):
#    '''
#    This function creates a self-signed server certificate with:
#     * default common name, organization, and country
#     * maximum validity period
#    It returns the certificate and the keypair.
#    '''
#    subj = X509.X509_Name()
#    subj.CN = cn
#    subj.C = country
#    subj.O = org
#
#    # maximum possible validity time frame
#    now = long(time.time())
#    not_before = ASN1.ASN1_UTCTIME()
#    not_before.set_time(0)
#    not_after = ASN1.ASN1_UTCTIME()
#    not_after.set_time(2 ** 31)
#
#    # build a list of extensions
#    #X509v3 Basic Constraints: CA:FALSE
#    exts = []
#    #ext = X509.new_extension('basicConstraints', 'CA:FALSE')
#    #ext.set_critical(1)
#    #exts.append(ext)
#    #Netscape Cert Type:
#    #SSL Server
#    #ext = X509.new_extension('nsCertType', 'SSL Server')
#    #exts.append(ext)
#
#    return mk_selfsigned_certnkey(2, 1, not_before, not_after, subj, 1024, exts)
#
#
#def mk_selfsigned_replica_certnkey(orig_cert):
#    '''
#    This function creates a self-signed replica of the given certificate. It returns a tuple of certificate and
#    Most of the fields of the original certificates are replicated:
#     * key length
#     * subject
#     * validity dates
#     * serial number
#     * version
#     * extensions
#    Couple parameters don't get replicated (because I don't know where to find them in M2Crypto.X509 object):
#     * public key exponent which is fixed to 65537,
#     * signature algorithm which is fixed to sha1WithRSAEncryption.
#    '''
#    public_key = orig_cert.get_pubkey()
#    bits = public_key.get_rsa().__len__()
#    subj = orig_cert.get_subject()
#    not_after = orig_cert.get_not_after()
#    not_before = orig_cert.get_not_before()
#    serial_number = orig_cert.get_serial_number()
#    version = orig_cert.get_version()
#    exts = []
#    for i in range(orig_cert.get_ext_count()):
#        exts.append(orig_cert.get_ext_at(i))
#
#    return mk_selfsigned_certnkey(version, serial_number, not_before, not_after, subj, bits, exts)
#
#def grab_server_cert(host, port):
#    '''
#    This function connects to the specified server and grabs its certificate.
#    '''
#    # create context
#    ctx = SSL.Context() # XXX should we try different protocols here
#    ctx.set_allow_unknown_ca(True)
#    ctx.set_verify(SSL.verify_none, 0)
#
#    # establish connection
#    sslsock = SSL.Connection(ctx)
#    sslsock.set_post_connection_check_callback(None)
#    sslsock.connect((host, port))
#
#    # grab server certificate and shut the connection
#    server_cert = sslsock.get_peer_cert()
#    sslsock.close()
#
#    return server_cert
