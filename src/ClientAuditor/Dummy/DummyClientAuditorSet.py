from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.Dummy.DummyClientAuditor import DummyClientConnectionAuditor

class DummyClientAuditorSet(ClientAuditorSet):
    '''
    This is a dummy profile set, containing only one dummy profile.
    '''
    NAUDITORS=3
    def __init__(self, _):
        auditors = []
        for i in range(self.NAUDITORS):
            auditors.append(DummyClientConnectionAuditor(i))
        ClientAuditorSet.__init__(self, auditors)
