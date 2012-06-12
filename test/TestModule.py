import logging
import unittest
from sslcaudit.core.BaseClientAuditController import BaseClientAuditController
from sslcaudit.core.ConnectionAuditEvent import ConnectionAuditResult
from sslcaudit.core.FileBag import FileBag
from sslcaudit.test.TestConfig import *
from sslcaudit.ui import SSLCAuditUI

def mk_sslcaudit_argv(user_cn=TEST_USER_CN):
    return [
        '--user-cn', user_cn,
        '--user-cert', TEST_USER_CERT_FILE,
        '--server', TEST_SERVER,
        '--user-key', TEST_USER_KEY_FILE,
        '--user-ca-cert', TEST_USER_CA_CERT_FILE,
        '--user-ca-key', TEST_USER_CA_KEY_FILE
    ]


def compare_eccar_with_accar(eccar, accar):
    '''
    This function compares an expected result with an actual result,
    '''
    if not (eccar.profile_spec == accar.profile.get_spec()):
        return False

    if eccar.expected_result == accar.result:
        return True
    else:
        return False


class ECCAR(object):
    '''
    Expected client connection audit result.
    '''

    def __init__(self, profile_spec, expected_res):
        self.profile_spec = profile_spec
        self.expected_result = expected_res

    def __eq__(self, other):
        if isinstance(other, ECCAR):
            return self.__dict__ == other.__dict__
        elif isinstance(other, ACCAR):
            return compare_eccar_with_accar(self, other)
        else:
            raise ValueError()

    def __hash__(self):
        h = self.profile_spec.__hash__()
        #        print 'ECCAR::hash("%s") = %d' % (self.profile_spec, h)
        return h

    def __repr__(self):
        return "ECCAR(%s, %s)" % (self.profile_spec, self.expected_result)


class ACCAR(object):
    '''
    Actual client connection audit result.
    '''

    def __init__(self, ccar):
        self.profile = ccar.profile
        self.result = ccar.result

    def __eq__(self, other):
        if isinstance(other, ACCAR):
            return self.__dict__ == other.__dict__
        elif isinstance(other, ECCAR):
            return compare_eccar_with_accar(other, self)
        else:
            raise ValueError()

    def __hash__(self):
        profile_spec = self.profile.get_spec()
        h = profile_spec.__hash__()
        #        print 'ACCAR::hash("%s") = %d' % (profile_spec, h)
        return h

    def __repr__(self):
        return "ACCAR(%s, %s)" % (self.profile.get_spec(), self.result)


class TestModule(unittest.TestCase):
    '''
    This is a base class for testing modules of sslcaudit tool.
    '''

    def setUp(self):
        self.controller = None

    def tearDown(self):
        if self.controller is not None:
            self.controller.stop()

    def _main_test(self, main_args, hammer, expected_results):
        '''
        This is a main worker function. It allocates external resources and launches threads,
        to make sure they are freed this function was to be called exactly once per test method,
        to allow tearDown() method to cleanup properly.
        '''
        self._main_test_init(main_args, hammer)
        self._main_test_do(expected_results)

    def _main_test_init(self, args, hammer):
        # allocate port
        port = get_next_listener_port()

        # collect classes of observed audit results
        self.actual_results = []

        def main__handle_result(res):
            #self.orig_main__handle_result(res)
            if isinstance(res, ConnectionAuditResult):
                self.actual_results.append(ACCAR(res))
            else:
                pass # ignore other events

        # create options for the controller
        main_args = ['-l', '%s:%d' % (TEST_LISTENER_ADDR, port)]
        main_args.extend(args)
        options = SSLCAuditUI.parse_options(main_args)

        # create file_bag and controller
        file_bag = FileBag(basename='test-sslcaudit', use_tempdir=True)
        self.controller = BaseClientAuditController(options, file_bag, event_handler=main__handle_result)

        self.hammer = hammer
        if self.hammer is not None:
            self.hammer.set_peer((TEST_LISTENER_ADDR, port))

    def _main_test_do(self, expected_results):
        # run the server
        self.controller.start()

        # start the hammer, if any
        if self.hammer is not None:
            self.hammer.start()

        # wait for main to finish its job
        self.controller.join(timeout=TEST_MAIN_JOIN_TIMEOUT)
        # on timeout throws exception, which we let propagate after we shut the hammer and the main thread

        self.assertFalse(self.controller.is_alive(), 'main thread is still alive')

        # stop the hammer if any
        if self.hammer is not None:    self.hammer.stop()

        # stop the server
        self.controller.stop()

        self.verify_results_ignore_order(expected_results, self.actual_results)

    def verify_results_ignore_order(self, expected_results, actual_results):
        expected_results_set = set(expected_results)
        actual_results_set = set(actual_results)

        unexpected = actual_results_set.difference(expected_results_set)
        missing = expected_results_set.difference(actual_results_set)

        if len(unexpected) != 0 or len(missing) != 0:
            print
        if len(unexpected) > 0:
            print '\tunexpected results: %s' % unexpected
        if len(missing) > 0:
            print '\tmissing results: %s' % missing
        self.assertTrue(len(unexpected) == 0 and len(missing) == 0, 'there are missing or unexpected results')


def init_logging(cls):
    logging.basicConfig(level=logging.DEBUG)
