''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from src.modules.base.BaseClientAuditorSet import BaseClientAuditorSet
from src.modules.dummy.DummyClientConnectionAuditor import DummyClientConnectionAuditor

class ClientAuditorSet(BaseClientAuditorSet):
    '''
    This is a dummy auditor set, containing only two dummy auditors.
    '''
    def __init__(self, file_bag, options):
        BaseClientAuditorSet.__init__(self, file_bag, options)

        self.add_auditor(DummyClientConnectionAuditor(False))
        self.add_auditor(DummyClientConnectionAuditor(True))
