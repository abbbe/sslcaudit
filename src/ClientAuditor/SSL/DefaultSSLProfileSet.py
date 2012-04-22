from src.ClientAuditor.ClientAuditorProfileSet import ClientAuditorProfileSet
from src.ClientAuditor.SSL.SelfSignedSSLProfile import SelfSignedSSLProfile

class DefaultSSLProfileSet(ClientAuditorProfileSet):
    def __init__(self):
        ClientAuditorProfileSet.__init__(self, [
            SelfSignedSSLProfile()
        ])
