from txjsonrpc.test import certs
from txjsonrpc.web import jsonrpc
from twisted.web import server
from twisted.internet import reactor, ssl

class Math(jsonrpc.JSONRPC):
    """
    An example object to be published.
    """
    def jsonrpc_add(self, a, b):
        """
        Return sum of arguments.
        """
        return a + b

sslContext = ssl.DefaultOpenSSLContextFactory(
	certs.key_file('pyserver'),
    certs.cert_file('pyserver')
#    certs.key_file('127.0.0.1'),
#    certs.cert_file('127.0.0.1')
)

reactor.listenSSL(
	7443,
	server.Site(Math()),
	contextFactory = sslContext,
)
reactor.run()

