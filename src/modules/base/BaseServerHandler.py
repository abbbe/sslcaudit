''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class BaseServerHandler(object):
    '''
    This is an abstract class for a server handler profile. Each module is expected to contain one or more
    subclasses of this class. Instances of those subclasses are normally created and contained by a subclass of
    BaseClientAuditor, when a module gets loaded during program startup.

    Subclasses of this class contain module-specific data and functionality necessary to audit incoming connections.
    Their handle() method will be invoked from ClientHandler and are expected to treat given connection and return
    ClientConnectionAuditResult describing the outcome of the test.

    Apart from overriding handle() method, the subclasses of this class have to provide a name which will be used in
    the output of the program. The name has to be descriptive enough to indicate what tests have been performed.
    '''

    def __init__(self, name='BaseServerHandler'):
        self.name = name

    def handle(self, conn):
        '''
        This method is invoked to audit a given client connection. It must return a valid ClientAuditResult object.
        This method gets invoked for multiple times, for different client connections, so it must not change the state
        of the object itself.
        '''
        raise NotImplementedError(
            'subclasses must override this method and return instances of ClientConnectionAuditResult')
