''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.modules.dummy.DummyClientAuditor import DummyClientConnectionAuditor

class AuditorSet(ClientAuditorSet):
    '''
    This is a dummy auditor set, containing only two dummy auditors.
    '''
    def __init__(self, _):
        auditors = [DummyClientConnectionAuditor(False), DummyClientConnectionAuditor(True)]
        ClientAuditorSet.__init__(self, auditors)
