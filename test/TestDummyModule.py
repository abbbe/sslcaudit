''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
from threading import Thread
import unittest
from sslcaudit.core import SSLCAuditUI
from sslcaudit.core.BaseClientAuditController import BaseClientAuditController
from sslcaudit.core.FileBag import FileBag
from sslcaudit.core.ClientConnectionAuditEvent import ClientAuditStartEvent, ClientAuditEndEvent, ClientConnectionAuditResult
from sslcaudit.core.ClientHandler import ClientAuditResult
from sslcaudit.test.TCPConnectionHammer import TCPConnectionHammer
from sslcaudit.test.TestConfig import get_next_listener_port, TEST_LISTENER_ADDR

class TestDummyModule(unittest.TestCase):
    '''
    test dummy client / auditor, no SSL whatsoever
    '''
    logger = logging.getLogger('TestDummyModule')
    MAIN_JOIN_TIMEOUT = 5
    HAMMER_ATTEMPTS = 3

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
        self.hammer = TCPConnectionHammer(self.HAMMER_ATTEMPTS)

        # create main, the target of the test
        main_args = ['-m', 'dummy', '-l', ("%s:%d" % (TEST_LISTENER_ADDR, port))]
        options = SSLCAuditUI.parse_options(main_args)
        file_bag = FileBag(basename='test-sslcaudit', use_tempdir=True)
        controller = BaseClientAuditController(options, file_bag, event_handler=main__handle_result)

        # tell the hammer how many attempts to make exactly
        self.hammer.set_peer((TEST_LISTENER_ADDR, port))

        # start server and client
        controller.start()
        self.hammer.start()

        controller.join(timeout=5)
        self.hammer.stop()

        # make sure we have received expected number of results
        self.assertEquals(self.got_result_start, 1)
        self.assertEquals(self.got_result, 2)
        self.assertEquals(self.got_result_end, 1)
        self.assertEquals(self.got_bulk_result, 1)
        self.assertEquals(self.nstray, 0)


if __name__ == '__main__':
    unittest.main()

