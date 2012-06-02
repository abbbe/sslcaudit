# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging, time
from socket import socket
from sslcaudit.test.ConnectionHammer import ConnectionHammer

class TCPConnectionHammer(ConnectionHammer):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    Normally used for unit tests only.
    '''
    logger = logging.getLogger('TCPConnectionHammer')

    def hammer(self, nround):
        # connect to the peer, do something, disconnect
        sock = socket()
        try:
            self.logger.debug('opening connection %s (round %d) ...', self.peer, nround)
            sock.connect(self.peer)
            self.logger.debug('round %d: connection to %s is established, waiting for %.1fs before closing',
                nround, self.peer, self.delay_before_close)
            time.sleep(self.delay_before_close)

        except Exception as ex:
            self.logger.debug('round %d: connection to %s has failed: %s', nround, self.peer, ex)
        finally:
            sock.close()
            self.logger.debug("round %d: connection with %s is closed", nround, self.peer)
