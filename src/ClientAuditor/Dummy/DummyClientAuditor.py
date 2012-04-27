from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult, PositiveAuditResult, NegativeAuditResult
from src.ClientAuditor.ClientConnectionAuditor import  ClientConnectionAuditor

class DummyClientConnectionAuditor(ClientConnectionAuditor):
    '''
    This dummy profile does nothing, but returns DummyClientConnectionResult.
    '''

    def __init__(self, dummy_result):
        ClientConnectionAuditor.__init__(self, dummy_result)
        self.dummy_result = dummy_result

    def handle(self, conn):
        if self.dummy_result:
            return ClientConnectionAuditResult(self, conn.get_client_id(), PositiveAuditResult('all ok'))
        else:
            return ClientConnectionAuditResult(self, conn.get_client_id(), NegativeAuditResult('not ok', 'all ok'))
