''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
import unittest
from src.ClientAuditor.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndEvent, ClientConnectionAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.Main import Main
from src.Test.TCPHammer import TCPHammer
from src.Test.TestConfig import get_next_listener_port, TEST_LISTENER_ADDR

class TestMainDummy(unittest.TestCase):
    '''
    Test dummy client / auditor, no SSL whatsoever
    '''
    logger = logging.getLogger('TestMainDummy')
    MAIN_JOIN_TIMEOUT = 5

    def test_dummy(self):
        '''
        This test establishes a bunch of plain TCP connections against dummy auditor.
        The dummy auditor just acknowledges the fact of connection happening.
        '''
        # these variables will be updated from a hook function invoked from main
        self.got_result_start = 0
        self.got_result = 0
        self.got_result_end = 0
        self.got_bulk_result = 0
        self.nstray = 0

        # the hook function
        def main__handle_result(res):
            '''
            This function overrides main.handle_result() and updates our counters
            '''
            if isinstance(res, ClientAuditStartEvent):
                self.got_result_start = self.got_result_start + 1
            elif isinstance(res, ClientAuditEndEvent):
                self.got_result_end = self.got_result_end + 1
            elif isinstance(res, ClientConnectionAuditResult):
                self.got_result = self.got_result + 1
            elif isinstance(res, ClientAuditResult):
                self.got_bulk_result = self.got_bulk_result + 1
            else:
                self.nstray = self.nstray + 1

        # allocate port
        port = get_next_listener_port()

        # create a client hammering our test listener
        self.hammer = TCPHammer()

        # create main, the target of the test
        self.main = Main(['-m', 'dummy', '-l', TEST_LISTENER_ADDR, '-p', port])
        self.main.handle_result = main__handle_result

        # tell the hammer how many attempts to make exactly
        self.hammer.init_tcp((TEST_LISTENER_ADDR, port), self.main.auditor_set.len())

        # start server and client
        self.main.start()
        self.hammer.start()

        self.main.join(timeout=5)
        self.hammer.stop()
        self.main.stop()

        # make sure we have received expected number of results
        self.assertEquals(self.got_result_start, 1)
        self.assertEquals(self.got_result, self.main.auditor_set.len())
        self.assertEquals(self.got_result_end, 1)
        self.assertEquals(self.got_bulk_result, 1)
        self.assertEquals(self.nstray, 0)


if __name__ == '__main__':
    unittest.main()

