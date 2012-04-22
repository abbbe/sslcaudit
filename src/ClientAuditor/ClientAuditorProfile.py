class ClientAuditResult(object):
    pass

class ClientAuditorProfile(object):
    '''Base class for a client auditor. Contain information necessary to perform an audit of a single client connection.'''
    def handle(self, socket):
        raise NotImplementedError('subclasses must override this method')
