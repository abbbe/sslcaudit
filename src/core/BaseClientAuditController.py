from Queue import Empty
from exceptions import Exception
import logging
import sys
from threading import Thread
from src.core.ClientAuditorServer import ClientAuditorServer
from src.core.ClientConnectionAuditEvent import ClientAuditResult
from src.core.ConfigErrorException import ConfigErrorException
from src.core.FileBag import FileBag
from src.test.ExternalCommandHammer import CurlHammer
from src.test.SSLConnectionHammer import ChainVerifyingSSLConnectionHammer, CNVerifyingSSLConnectionHammer
from src.test.TCPConnectionHammer import TCPConnectionHammer

HOST_ADDR_ANY = '0.0.0.0'

MODULE_MODULE_NAME_PREFIX = 'src.modules'
PROFILE_FACTORY_MODULE_NAME = 'ProfileFactory'
PROFILE_FACTORY_CLASS_NAME = 'ProfileFactory'

PROG_NAME = 'sslcaudit'
PROG_VERSION = '1.0rc1'

class BaseClientAuditController(Thread):
    logger = logging.getLogger('BaseClientAuditController')

    def __init__(self, options):
        Thread.__init__(self, target=self.run)
        self.options = options
        self.queue_read_timeout = 0.1

        if self.options.debug_level > 0:
            logging.getLogger().setLevel(logging.DEBUG)

        self.file_bag = FileBag(self.options.test_name)

        self.init_profile_factories()

        self.server = ClientAuditorServer(self.options.listen_on, self.profile_factories)
        self.res_queue = self.server.res_queue

        self.init_self_tests()

    def init_profile_factories(self):
        self.profile_factories = []

        for module_name in self.options.modules.split(','):
            # load the module from under MODULE_NAME_PREFIX
            module_name = MODULE_MODULE_NAME_PREFIX + "." + module_name + '.' + PROFILE_FACTORY_MODULE_NAME
            try:
                __import__(module_name, fromlist=[])
            except Exception as ex:
                raise ConfigErrorException("Cannot load module ", module_name, ", exception: ", ex)

            # find and instantiate the profile factory class
            profile_factory_class = sys.modules[module_name].__dict__[PROFILE_FACTORY_CLASS_NAME]
            self.profile_factories.append(profile_factory_class(self.file_bag, self.options))

        # there must be some profile factories in the list, otherwise we die right here
        if len(self.profile_factories) == 0:
            raise ConfigErrorException("no single profile factory, nothing to do")

    def start(self):
        self.do_stop = False
        self.server.start()
        Thread.start(self)

        if self.selftest_hammer is not None:
            self.selftest_hammer.start()

    def stop(self):
        # signal the controller thread to stop
        self.do_stop = True

    def run(self):
        '''
        SSLCAuditCLI loop function. Will run until the desired number of clients is handled.
        '''
        nresults = 0

        # loop until get all desired results, quit if stopped
        while nresults < self.options.nclients and not self.do_stop:
            try:
                # wait for a message blocking for short intervals, check stop flag frequently
                res = self.server.res_queue.get(True, self.queue_read_timeout)
                self.logger.debug("got result %s", res)
                self.handle_result(res)

                if isinstance(res, ClientAuditResult):
                    nresults = nresults + 1
            except Empty:
                pass

    def handle_result(self, res):
        raise NotImplemented('subclasses must override this method')

    def init_self_tests(self):
        # determine where to connect to
        if self.options.listen_on_addr == HOST_ADDR_ANY:
            peer_host = 'localhost'
        else:
            peer_host = self.options.listen_on_addr
        peer = (peer_host, self.options.listen_on_port)

        # instantiate hammer class
        if self.options.self_test is None:
            self.selftest_hammer = None
        else:
            if self.options.self_test == 0:
                self.selftest_hammer = TCPConnectionHammer(-1)

            elif self.options.self_test == 1:
                if self.options.user_cn is not None:
                    self.selftest_hammer = CNVerifyingSSLConnectionHammer(-1, 'hello')
                else:
                    raise ConfigErrorException('test mode 1 requires --user-cn')

            elif self.options.self_test == 2:
                if self.options.user_ca_cert_file is not None:
                    self.selftest_hammer = CurlHammer(-1, self.options.user_ca_cert_file)
                else:
                    raise ConfigErrorException('test mode 2 requires --user-ca-cert/--user-ca-key')
            else:
                raise ConfigErrorException('Invalid selftest number %d' % self.options.self_test)

            # set the peer for the hammer
            self.selftest_hammer.set_peer(peer)
