''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class ClientConnectionAuditEvent(object):
    '''
    This is a base class for events produced by connection auditors
    '''
    def __init__(self, auditor, conn):
        self.auditor = auditor
        self.conn = conn

    def __eq__(self, other):
        return (self.__class__ == other.__class__) and (self.__dict__ == other.__dict__)


class ClientConnectionAuditResult(ClientConnectionAuditEvent):
    '''
    This is a base class for audit results returned by ClientConnectionAuditor.handle() method.
    It contains the results of the audit of a single connection.
    '''

    def __init__(self, auditor, conn, res):
        ClientConnectionAuditEvent.__init__(self, auditor, conn)
        self.res = res

    def __str__(self):
        return ' CCAR(%s, %s, %s)' % (self.auditor.name, self.conn.get_client_id(), self.res)

class ClientAuditStartEvent(ClientConnectionAuditEvent):
    pass


class ClientAuditEndEvent(ClientConnectionAuditEvent):
    pass
