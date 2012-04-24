import logging
from socket import socket
from threading import Thread
import time

logging.getLogger('PlainTCPClient').setLevel(logging.INFO)

class PlainTCPClient(Thread):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    Normally used for unit tests only.
    '''
    logger = logging.getLogger('PlainTCPClient')

    RECONNECT_ATTEMPTS = 3
    RECONNECT_DELAY = 1

    def __init__(self, peer, nattempts=RECONNECT_ATTEMPTS, delay=RECONNECT_DELAY):
        Thread.__init__(self, target=self.run)
        self.peer = peer
        self.daemon = True
        self.should_stop = False

    def run(self):
        self.logger.debug("running %s", self)
        for _ in range(self.RECONNECT_ATTEMPTS):
            if self.should_stop: break
            self.connect()
            time.sleep(self.RECONNECT_DELAY)
        self.logger.debug("exiting %s", self)

    def connect(self):
        self.logger.debug("connecting to %s", self.peer)
        s = socket()
        try:
            s.connect(self.peer)
        except:
            self.logger.error("connection failed")
            pass

        s.close()

    def stop(self):
        self.logger.debug("stopping %s", self)
        self.should_stop = True
