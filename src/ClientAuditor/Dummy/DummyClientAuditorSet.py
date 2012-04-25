from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.Dummy.DummyClientAuditor import DummyClientConnectionAuditor

class DummyClientAuditorSet(ClientAuditorSet):
    '''
    This is a dummy profile set, containing only one dummy profile.
    '''
    def __init__(self, _):
        auditors = [DummyClientConnectionAuditor(False), DummyClientConnectionAuditor(True)]
        ClientAuditorSet.__init__(self, auditors)
