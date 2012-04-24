from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.SSL.SelfSignedSSLClientAuditor import SelfSignedSSLClientConnectionAuditor

class SSLClientAuditorSet(ClientAuditorSet):
    def __init__(self, options):
        ClientAuditorSet.__init__(self, [
            SelfSignedSSLClientConnectionAuditor()
        ])
        self.options = options

        if self.options.has_key('server'):
            server_cert = grab_server_cert(self.options['server'])
