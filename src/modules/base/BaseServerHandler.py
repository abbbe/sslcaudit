''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class BaseServerHandler(object):
    '''
    This is an abstract class for a server handler. Each client testing module is expected to at least one
    subclass of this class. An instance that subclass are normally contained in a subclass of BaseProfileFactory,
    created when the module gets loaded during program startup.

    Subclasses of this class contain module-specific behavior and functionality to test incoming connections using
    module-specific profiles.
    '''

    def handle(self, conn, profile):
        '''
        This method will be invoked by ClientHandler when new client connection arrives. It is expected to treat given
        connection using given profile and return ClientConnectionAuditResult describing the outcome. This method gets
        invoked multiple times, for different client connections, for different profiles, so it must not change the
        state of the object itself and be thread-safe.
        '''
        raise NotImplementedError('subclasses must override this method')
