''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from src.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.modules.base.BaseClientConnectionAuditor import BaseClientConnectionAuditor

class DummyClientConnectionAuditor(BaseClientConnectionAuditor):
    '''
    This dummy profile does nothing, but returns an result it is given.
    '''

    def __init__(self, dummy_result):
        BaseClientConnectionAuditor.__init__(self, dummy_result)
        self.dummy_result = dummy_result

    def handle(self, conn):
        return ClientConnectionAuditResult(self, conn, self.dummy_result)
