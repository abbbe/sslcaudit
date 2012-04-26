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

# ----------------------------------------------------------------------------------

class PositiveAuditResult(ClientConnectionAuditResult):
    '''
    The client has established SSL session. The client is vulnerable to MITM.
    '''


class NegativeAuditResult(ClientConnectionAuditResult):
    '''
    SSL connection has failed with expected exception code. The client is not vulnerable to MITM.
    '''


class TestPositiveAuditResult(ClientConnectionAuditResult):
    '''
    The client has established SSL connection, but it was expected to do so.
    Gives some assurance that the test setup ok.
    '''


class TestErrorAuditResult(ClientConnectionAuditResult):
    '''
    The client has failed to establish SSL connection, but was supposed to.
    Indicates something is wrong with the test setup.
    '''

# ----------------------------------------------------------------------------------

class ClientAuditStartEvent(ClientConnectionAuditEvent):
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    pass
