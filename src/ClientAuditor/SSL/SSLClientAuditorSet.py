from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.SSL.SelfSignedSSLClientAuditor import SelfSignedSSLClientAuditor

class SSLClientAuditorSet(ClientAuditorSet):
    def __init__(self):
        ClientAuditorSet.__init__(self, [
            SelfSignedSSLClientAuditor()
        ])
