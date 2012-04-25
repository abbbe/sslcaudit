import logging
from socket import socket
from threading import Thread
import time

class TCPClient(Thread):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    Normally used for unit tests only.
    '''
    logger = logging.getLogger('TCPClient')

    RECONNECT_DELAY = 0.5

    def __init__(self, peer, nattempts, delay=RECONNECT_DELAY):
        Thread.__init__(self, target=self.run)
        self.peer = peer
        self.nattempts = nattempts
        self.daemon = True
        self.should_stop = False

    def run(self):
        self.logger.debug("running %s", self)
        for _ in range(self.nattempts):
            if self.should_stop: break
            self.connect()
            time.sleep(self.RECONNECT_DELAY)
        self.logger.debug("exiting %s", self)

    def connect(self):
        '''
        This method tries to establish a plain TCP connection to the peer.
        If successful, it invokes connect_l4()
        '''
        self.logger.debug("connecting to %s", self.peer)
        sock = socket()
        try:
            sock.connect(self.peer)
            self.connect_l4(sock)
        except Exception as ex:
            self.logger.debug('connection failed: %r', ex)
            pass

        sock.close()

    def connect_l4(self, s):
        '''
        Subclasses can override this method to establish application-layer protocol connection
        '''
        pass

    def stop(self):
        self.logger.debug("stopping %s", self)
        self.should_stop = True
