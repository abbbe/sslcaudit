''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from src.test.Hammer import Hammer

DEFAULT_DELAY_BEFORE_CLOSE = 1

class ConnectionHammer(Hammer):
    def __init__(self, nattempts):
        Hammer.__init__(self, nattempts)
        self.peer = None
        self.delay_before_close = DEFAULT_DELAY_BEFORE_CLOSE

    def set_peer(self, peer):
        self.peer = peer
        self.logger.info('initialized with peer %s' % str(self.peer))

