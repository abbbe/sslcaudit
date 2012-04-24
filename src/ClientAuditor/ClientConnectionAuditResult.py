class ClientConnectionAuditResult(object):
    '''
    This is a base class for audit results returned by ClientConnectionAuditor.handle() method. It
    contains the results of the audit of a single connection.
    '''

    def __init__(self, client_id):
        self.client_id = client_id


class ClientConnectionAuditResultStart(ClientConnectionAuditResult):        pass


class ClientConnectionAuditResultEnd(ClientConnectionAuditResult):        pass
