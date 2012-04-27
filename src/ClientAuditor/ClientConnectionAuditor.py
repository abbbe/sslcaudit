''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automatingsecurity audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
class ClientConnectionAuditor(object):
    '''
    Base class for a client connection auditor. It has to contain information needed by handle() method
    to perform some specific tests of a single client connection.
    '''
    def __init__(self, name):
        self.name = name


    def handle(self, conn):
        '''
        This method is invoked to audit a given client connection. It must return a valid ClientAuditResult object.
        This method gets invoked for multiple times, for different client connections, so it must not change the state
        of the object itself.
        '''
        raise NotImplementedError('subclasses must override this method and return a valid ClientAuditResult()')
