from Queue import Empty
from exceptions import Exception
import logging
import sys
from threading import Thread
from src.core.ClientAuditorServer import ClientAuditorServer
from src.core.ClientConnectionAuditEvent import ClientAuditResult
from src.core.ConfigErrorException import ConfigErrorException
from src.core.FileBag import FileBag

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = '8443'
DEFAULT_MODULES = 'sslcert'

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

        if self.options.debug_level > 0:
            logging.getLogger().setLevel(logging.DEBUG)

        self.file_bag = FileBag(self.options.test_name)

        self.init_profile_factories()

        self.server = ClientAuditorServer(self.options.listen_on, self.profile_factories)
        self.res_queue = self.server.res_queue

        self.queue_read_timeout = 0.1

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

    def stop(self):
        # signal the thread to stop
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