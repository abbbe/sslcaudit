import unittest, time, logging
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.PlainTCPClient import PlainTCPClient
from src.ClientAuditor.ClientConnectionAuditResult import ClientConnectionAuditResultEnd, ClientConnectionAuditResultStart, ClientConnectionAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.Main import Main

logging.basicConfig(level=logging.DEBUG)

TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_PORT = 9999

class TestMain(unittest.TestCase):
    '''
    This class tests ClientAuditorServer.
    '''
    GETRESULT_TIMEOUT = 5
    logger = logging.getLogger('TestMain')

    def test(self):
        '''
        Establish a bunch of plain TCP connections against dummy auditor.
        '''
        self.got_result_start = 0
        self.got_result = 0
        self.got_result_end = 0
        self.got_bulk_result = 0

        def main__handle_result(res):
            '''
            This function overrides main.handle_result() and updates our counters
            '''
            if isinstance(res, ClientConnectionAuditResultStart):
                self.got_result_start = self.got_result_start + 1
            elif isinstance(res, ClientConnectionAuditResultEnd):
                self.got_result_end = self.got_result_end + 1
            elif isinstance(res, ClientConnectionAuditResult):
                self.got_result = self.got_result + 1
            elif isinstance(res, ClientAuditResult):
                self.got_bulk_result = self.got_bulk_result + 1

        # create main, the target of the test
        main = Main(['-m', 'dummy', '-l', TEST_LISTENER_ADDR, '-p', TEST_LISTENER_PORT])
        main.handle_result = main__handle_result
        main.start()

        # create a client hammering our test listener
        plain_tcp_client = PlainTCPClient((TEST_LISTENER_ADDR, TEST_LISTENER_PORT))
        plain_tcp_client.start()

        # wait until we receive expected number of results
        while not (self.got_result_start == 1 and self.got_result == DummyClientAuditorSet.NAUDITORS
                and self.got_result_end == 1 and self.got_bulk_result == 1):
            time.sleep(1)

        plain_tcp_client.stop()

if __name__ == '__main__':
    unittest.main()
