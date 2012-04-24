from threading import Thread
import unittest, time
import logging
from socket import socket
from src.ClientAuditor.ClientAuditor import ClientAuditResultEnd
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet

logger = logging.getLogger('TestDummyClientAuditor')

TEST_HOST = 'localhost'
TEST_PORT = 9999
RECONNECT_ATTEMPTS = 5
RECONNECT_PERIOD = 1

class DummyClient(Thread):
    '''
    This class continuously tries to connect to the specified host and port.
    After connection is established, it immediately closes it.
    '''

    def __init__(self, host, port):
        Thread.__init__(self, target=self.run)
        self.host = host
        self.port = port
        self.daemon = True
        self.should_stop = False

    def run(self):
        logger.debug("running %s", self)
        for _ in range(RECONNECT_ATTEMPTS):
            if self.should_stop: break
            self.connect()
            time.sleep(RECONNECT_PERIOD)
        logger.debug("exiting %s", self)

    def connect(self):
        logger.debug("connecting to %s:%s", self.host, self.port)
        s = socket()
        s.connect((self.host, self.port))
        s.close()

    def stop(self):
        logger.debug("stopping connection %s:%s", self.host, self.port)
        self.should_stop = True

GETRESULT_TIMEOUT = 5

class TestDummyClientAuditor(unittest.TestCase):
    def test(self):
        auditor_set = DummyClientAuditorSet()
        server = ClientAuditorServer((TEST_HOST, TEST_PORT), auditor_set)
        server.start()

        dummy_client = DummyClient(TEST_HOST, TEST_PORT)
        dummy_client.start()

        while True:
            logger.debug('getting a result from the queue')
            res = server.res_queue.get(timeout = GETRESULT_TIMEOUT)
            logger.debug('got result %s', res)

            if isinstance(res, ClientAuditResultEnd):
                break

        dummy_client.stop()

if __name__ == '__main__':
        logging.basicConfig(level = logging.DEBUG)
        unittest.main()

