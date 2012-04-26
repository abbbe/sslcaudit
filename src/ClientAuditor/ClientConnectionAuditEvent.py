class ClientConnectionAuditEvent(object):
    def __init__(self, auditor, client_id):
        self.auditor = auditor
        self.client_id = client_id


class ClientConnectionAuditResult(ClientConnectionAuditEvent):
    '''
    This is a base class for audit results returned by ClientConnectionAuditor.handle() method.
    It contains the results of the audit of a single connection.
    '''
    class Positive(object):
        '''
        The outcome of the test is as expected.
        '''
        def __init__(self, actual):
            self.actual = actual

        def __eq__(self, other):
            return (self.__class__ == other.__class__) and (self.actual == other.actual)

        def __str__(self):
            return "+ got '%s'" % (self.actual)

    class Negative(object):
        '''
        The outcome of the test is as expected.
        '''
        def __init__(self, actual, expected):
            self.actual = actual
            self.expected = expected

        def __eq__(self, other):
            return (self.__class__ == other.__class__) and (self.actual == other.actual) and (self.expected == other.expected)

        def __str__(self):
            return "- got '%s' expected '%s'" % (self.actual, self.expected)

    def __init__(self, auditor, client_id, actual, expected=None):
        ClientConnectionAuditEvent.__init__(self, auditor, client_id)
        if expected == None:
            self.res = self.Positive(actual)
        else:
            self.res = self.Negative(actual, expected)

# ----------------------------------------------------------------------------------

class ClientAuditStartEvent(ClientConnectionAuditEvent):
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    pass
