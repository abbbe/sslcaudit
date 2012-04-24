from src.ClientAuditor.ClientConnectionAuditResult import ClientConnectionAuditResult
from src.ClientAuditor.ClientConnectionAuditor import  ClientConnectionAuditor

class DummyResultClient(ClientConnectionAuditResult):
    def __init__(self, client_id, dummy_result):
        ClientConnectionAuditResult.__init__(self, client_id)
        self.dummy_result = dummy_result

    def __repr__(self):
        return 'DummyResultClient(%s, %s)' % (self.client_id, self.dummy_result)


class DummyClientConnectionAuditor(ClientConnectionAuditor):
    '''
    This dummy profile does nothing, but returns DummyResultClient.
    '''

    def __init__(self, dummy_result):
        self.dummy_result = dummy_result

    def handle(self, conn):
        return DummyResultClient(conn.get_client_id(), self.dummy_result)

    def __repr__(self):
        return self.__class__.__name__
