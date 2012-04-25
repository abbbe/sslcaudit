from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult, PositiveAuditResult, NegativeAuditResult
from src.ClientAuditor.ClientConnectionAuditor import  ClientConnectionAuditor

class DummyClientConnectionAuditor(ClientConnectionAuditor):
    '''
    This dummy profile does nothing, but returns DummyClientConnectionResult.
    '''

    def __init__(self, dummy_result):
        self.dummy_result = dummy_result

    def handle(self, conn):
        if self.dummy_result:
            return PositiveAuditResult(self, conn.get_client_id(), "kinda vulnerable to MITM")
        else:
            return NegativeAuditResult(self, conn.get_client_id(), "kinda not vulnerable to MITM")
