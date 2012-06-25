from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory, Protocol

CERTFILE='test/certs/www.example.com-cert.pem'
KEYFILE='test/certs/www.example.com-key.pem'

class AltCtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        ctx = ssl.ClientContextFactory.getContext(self)

        ctx.set_cipher_list('EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5')
        ctx.use_certificate_file(CERTFILE)
        ctx.use_privatekey_file(KEYFILE)

        return ctx


class Echo(Protocol):
    def dataReceived(self, data):
        """As soon as any data is received, write it back."""
        self.transport.write(data)


if __name__ == '__main__':
    factory = Factory()
    factory.protocol = Echo
    reactor.listenSSL(8443, factory, AltCtxFactory())
    reactor.run()
