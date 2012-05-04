''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
from socket import socket
from threading import Thread
import time
from src.modules.sslcert.SSLServerHandler import DEFAULT_SOCK_READ_TIMEOUT

class TCPHammer(Thread):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    Normally used for unit tests only.
    '''
    logger = logging.getLogger('TCPHammer')

    RECONNECT_DELAY = 0.5

    def __init__(self, name='TCPHammer'):
        Thread.__init__(self, target=self.run)
        self.name = name

    def __repr__(self):
        return self.name

    def init_tcp(self, peer, nattempts):
        self.peer = peer
        self.nattempts = nattempts
        self.daemon = True
        self.should_stop = False

        self.delay_before_close = DEFAULT_SOCK_READ_TIMEOUT.sec * 2

    def run(self):
        self.logger.debug("running %s", self)

        i = 0
        while (self.nattempts == -1 or i < self.nattempts) and not self.should_stop:
            # connect to the peer, do something, disconnect
            try:
                self.logger.debug("opening connection %d to %s ...", i, self.peer)
                sock = socket()
                sock.connect(self.peer)
                self.logger.debug("connection %d to %s established, handshaking ...", i, self.peer)
                self.connect_l4(sock)
                self.logger.debug("waiting %.1fs before closing connect %i with %s ..",
                    self.delay_before_close, i, self.peer)
                time.sleep(self.delay_before_close)
            except IOError as ex:
                self.logger.error('connection %d failed: %s', i, ex)
            finally:
                sock.close()
                self.logger.debug("connection %d with %s closed", i, self.peer)

            # wait a little while before repeating
            time.sleep(self.RECONNECT_DELAY)

            i += 1
        self.logger.debug("exiting %s", self)

    def connect_l4(self, sock):
        '''
        This method can be overridden by subclasses to do something after L3 connection is established
        '''
        pass

    def stop(self):
        self.logger.debug("stopping %s", self)
        self.should_stop = True
