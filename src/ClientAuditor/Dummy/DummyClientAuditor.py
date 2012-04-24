from src.ClientAuditor.ClientAuditor import ClientAuditResult, ClientAuditor

class DummyResult(ClientAuditResult):
    def __init__(self, client_id, dummy_result):
        ClientAuditResult.__init__(self, client_id)
        self.dummy_result = dummy_result

    def __repr__(self):
        return "DummyResult(%s, %s)" % (self.client_id, self.dummy_result)


class DummyClientAuditor(ClientAuditor):
    '''
    This dummy profile does nothing, but returns DummyResult.
    '''

    def __init__(self, dummy_result):
        self.dummy_result = dummy_result

    def handle(self, conn):
        return DummyResult(conn.get_client_id(), self.dummy_result)

    def __repr__(self):
        return self.__class__.__name__
