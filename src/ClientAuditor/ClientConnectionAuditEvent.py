''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
class ClientConnectionAuditEvent(object):
    def __init__(self, auditor, conn):
        self.auditor = auditor
        self.conn = conn

    def __eq__(self, other):
        return (self.__class__ == other.__class__) and (self.__dict__ == other.__dict__)

    def __repr__(self):
        return self.__dict__.__str__()

class ClientConnectionAuditResult(ClientConnectionAuditEvent):
    '''
    This is a base class for audit results returned by ClientConnectionAuditor.handle() method.
    It contains the results of the audit of a single connection.
    '''

    def __init__(self, auditor, conn, res):
        ClientConnectionAuditEvent.__init__(self, auditor, conn)
        self.res = res

    def __str__(self):
        return "%-20s %-10s %s" % (self.auditor.name, self.conn.get_client_id(), self.res)

#class AuditResult(object):
#    def __eq__(self, other):
#        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__
#
#
#class PositiveAuditResult(AuditResult):
#    '''
#    The outcome of the test is as expected.
#    '''
#
#    def __init__(self, actual):
#        self.actual = actual
#
#    def __repr__(self):
#        return "+ got '%s'" % (self.actual)
#
#
#class NegativeAuditResult(AuditResult):
#    '''
#    The outcome of the test is as expected.
#    '''
#
#    def __init__(self, actual, expected):
#        self.actual = actual
#        self.expected = expected
#
#    def __repr__(self):
#        return "- got '%s' expected '%s'" % (self.actual, self.expected)
#
#class TestFailureAuditResult(AuditResult):
#    '''
#    The outcome of the test suggests inconsistent test results.
#    '''
#
#    def __init__(self, actual, expected):
#        self.actual = actual
#        self.expected = expected
#
#    def __repr__(self):
#        return "! got '%s' expected '%s'" % (self.actual, self.expected)


# ----------------------------------------------------------------------------------

class ClientAuditStartEvent(ClientConnectionAuditEvent):
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    pass
