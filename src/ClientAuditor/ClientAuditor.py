class ClientAuditResult(object):
    '''
    This is a base class for audit results returned by ClientAuditor.handle() method. It
    contains the results of audit of a single connection.
    '''

    def __init__(self, client_id):
        self.client_id = client_id


class ClientAuditResultStart(ClientAuditResult):        pass


class ClientAuditResultEnd(ClientAuditResult):        pass


class ClientAuditor(object):
    '''
    Base class for a client auditor. It has to contain information needed by handle() method
    to perform some specific tests of a single client connection.
    '''

    def handle(self, conn):
        '''
        This method is invoked to audit a given client connection. It must return a valid ClientAuditResult object.
        This method gets invoked for multiple times, for different client connections, so it must not change the state
        of the object itself.
        '''
        raise NotImplementedError('subclasses must override this method and return a valid ClientAuditResult()')
