''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class BaseClientAuditorSet(object):
    '''
    This class contains a list of connection auditors (subclasses of BaseClientConnectionAuditor class). Each module is
    expected to contain a subclass of this class named ClientAuditorSet. One instance of that subclass will be created
    when module gets loaded during program startup. Its constructor will receive a dictionary of command-line options
    and is expected to populate the list of connection auditors by invoking add_auditor() method. The objects added into
    this list should extend BaseClientConnectionAuditor class.
    '''

    def __init__(self, options):
        self.options = options
        self.auditors = []

    def add_auditor(self, auditor):
        self.auditors.append(auditor)

    def __iter__(self):
        return self.auditors.__iter__()

    def len(self):
        return len(self.auditors)
