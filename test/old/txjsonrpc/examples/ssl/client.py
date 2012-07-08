import logging
from twisted.internet import reactor
from txjsonrpc.test import certs
from txjsonrpc.web.jsonrpc import Proxy

# --- twisted callbacks, taken from examples/tcp/client.py ---

def printValue(value):
    print "Result: %s" % str(value)

def printError(error):
    print 'error', error

def shutDown(data):
    print "Shutting down reactor..."
    reactor.stop()

# ------------------------------------------------------------

def server_cert_verify_callback(connection, x509, errnum, errdepth, ok):
    """
    This callback gets invoked by OpenSSL as a part of server certificate verification process.
    This implementation of the callback rejects invalid certificates and logs an error.
    If the certificate is valid it logs a debug message with the information about the certificate.
    """
    if not ok:
        log.msg('invalid server cert: %s' % x509.get_subject(), logLevel=logging.ERROR)
        return False
    else:
        log.msg('good server cert: %s' % x509.get_subject(), logLevel=logging.INFO)
        return True

from twisted.internet import ssl
from OpenSSL import SSL
from twisted.python import log

class AltCtxFactory(ssl.ClientContextFactory):
    """
    This factory create SSL contexts set for mutual client-server certificate validation.
     * present a certificate to the server.
     * validate chain of trust of the certificate of the server.
     * check CN of the server certificate
    """
    def __init__(self):
        # here we use certificates from txjsonrpc/test/certs/ directory
        self.ca_cert_file = certs.ca_cert_file()
        self.cert_file = certs.cert_file('pyclient')
        self.key_file = certs.key_file('pyclient')

    def getContext(self):
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.set_verify(SSL.VERIFY_PEER, server_cert_verify_callback)
        ctx.set_verify_depth(10)

        ctx.load_verify_locations(self.ca_cert_file)
        ctx.use_certificate_file(self.cert_file)
        ctx.use_privatekey_file(self.key_file)

        return ctx

# ------------------------------------------------------------
import sys
log.startLogging(sys.stdout)

if len(sys.argv) > 1:
    port = int(sys.argv[1])
else:
    port = 7443

proxy = Proxy('https://localhost:%d/' % port, ssl_ctx_factory=AltCtxFactory)

d = proxy.callRemote('add', 3, 5)
d.addCallback(printValue).addErrback(printError).addBoth(shutDown)
reactor.run()
