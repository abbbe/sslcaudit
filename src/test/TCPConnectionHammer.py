''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
from socket import socket
from src.test.Hammer import Hammer

class ConnectionHammer(Hammer):
    def __init__(self, peer):
        Hammer.__init__(self, nattempts)
        self.peer = peer
        self.delay_before_close = 60


class TCPConnectionHammer(ConnectionHammer):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    Normally used for unit tests only.
    '''
    logger = logging.getLogger('TCPConnectionHammer')



    def hammer(self, i):
        # connect to the peer, do something, disconnect
        try:
            self.logger.debug("opening connection %d to %s ...", i, self.peer)
            sock = socket()
            sock.connect(self.peer)
            self.logger.debug("connection %d to %s established, waiting for %.1fs before closing",
                i, self.peer, delay_before_close)

        except IOError as ex:
            self.logger.error('connection %d failed: %s', i, ex)
        finally:
            close()
            self.logger.debug("connection %d with %s closed", i, self.peer)
