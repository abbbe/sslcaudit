from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.Dummy.DummyClientAuditor import DummyClientConnectionAuditor

class DummyClientAuditorSet(ClientAuditorSet):
    '''
    This is a dummy profile set, containing only one dummy profile.
    '''

    def __init__(self):
        ClientAuditorSet.__init__(self,
            [DummyClientConnectionAuditor(1), DummyClientConnectionAuditor(2), DummyClientConnectionAuditor(3)])

    def __repr__(self):
        return self.__class__.__name__
