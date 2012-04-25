class ClientConnectionAuditEvent(object):
    def __init__(self, auditor, client_id):
        self.auditor = auditor
        self.client_id = client_id


class ClientConnectionAuditResult(ClientConnectionAuditEvent):
    '''
    This is a base class for audit results returned by ClientConnectionAuditor.handle() method. It
    contains the results of the audit of a single connection.
    '''

    def __init__(self, auditor, client_id, details):
        ClientConnectionAuditEvent.__init__(self, auditor, client_id)
        self.details = details


class PositiveAuditResult(ClientConnectionAuditResult):
    def __init__(self, auditor, client_id, details):
        ClientConnectionAuditResult.__init__(self, auditor, client_id, details)


class NegativeAuditResult(ClientConnectionAuditResult):
    def __init__(self, auditor, client_id, details):
        ClientConnectionAuditResult.__init__(self, auditor, client_id, details)


class ClientAuditStartEvent(ClientConnectionAuditEvent):
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    pass
