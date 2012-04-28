''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class ClientAuditorSet(object):
    '''
    This is a base class for sets of client auditors.
    '''

    def __init__(self, auditors):
        self.auditors = auditors

    def __iter__(self):
        return self.auditors.__iter__()

    def len(self):
        return len(self.auditors)
