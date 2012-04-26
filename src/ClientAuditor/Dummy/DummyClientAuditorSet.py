from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.Dummy.DummyClientAuditor import DummyClientConnectionAuditor

class DummyClientAuditorSet(ClientAuditorSet):
    '''
    This is a dummy auditor set, containing only two dummy auditors.
    '''
    def __init__(self, _):
        auditors = [DummyClientConnectionAuditor(False), DummyClientConnectionAuditor(True)]
        ClientAuditorSet.__init__(self, auditors)
