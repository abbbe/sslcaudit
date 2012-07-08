# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

from Queue import Empty
from exceptions import Exception
import logging
import sys
from threading import Thread
from sslcaudit.core import CFG_PTA_EXIT
from sslcaudit.core.ClientAuditorServer import ClientAuditorServer
from sslcaudit.core.ConnectionAuditEvent import SessionEndResult
from sslcaudit.core.ConfigError import ConfigError
from sslcaudit.test.ExternalCommandHammer import CurlHammer
from sslcaudit.test.SSLConnectionHammer import ChainVerifyingSSLConnectionHammer, CNVerifyingSSLConnectionHammer
from sslcaudit.test.TCPConnectionHammer import TCPConnectionHammer

HOST_ADDR_ANY = '0.0.0.0'

MODULE_MODULE_NAME_PREFIX = 'sslcaudit.modules'
PROFILE_FACTORY_MODULE_NAME = 'ProfileFactory'
PROFILE_FACTORY_CLASS_NAME = 'ProfileFactory'

PROG_NAME = 'sslcaudit'
PROG_VERSION = '1.1'

logger = logging.getLogger('BaseClientAuditController')

class BaseClientAuditController(Thread):

    def __init__(self, options, file_bag, event_handler):
        Thread.__init__(self, target=self.run, name='BaseClientAuditController')
        self.options = options
        self.event_handler = event_handler
        self.queue_read_timeout = 0.1

        self.file_bag = file_bag

        self.init_profile_factories()

        self.server = ClientAuditorServer(self.options.listen_on, self.profile_factories, options.post_test_action)
        self.res_queue = self.server.res_queue

        logger.debug('dumping options')
        for (key, value) in self.options.__dict__.items():
          logger.debug('\t%s = %s' % (key, value))
        logger.debug('end of options dump')
        logger.info('number of profile factories: %d' % len(self.profile_factories))
        for pf in self.profile_factories:
            logger.info('profile factory: %s', pf)

        # initialize the self test hammers
        # make sure we shut down the controller if there is a failure
        try:
            self.init_self_tests()
        except Exception as ex:
            self.server.server_close()
            raise ex

    def init_profile_factories(self):
        self.profile_factories = []

        for module_name in self.options.modules.split(','):
            # load the module from under MODULE_NAME_PREFIX
            module_name = MODULE_MODULE_NAME_PREFIX + "." + module_name + '.' + PROFILE_FACTORY_MODULE_NAME
            try:
                __import__(module_name, fromlist=[])
            except Exception as ex:
                raise ConfigError("cannot load module %s, exception: %s" % (module_name, ex))

            # find and instantiate the profile factory class
            profile_factory_class = sys.modules[module_name].__dict__[PROFILE_FACTORY_CLASS_NAME]
            self.profile_factories.append(profile_factory_class(self.file_bag, self.options))

        # there must be some profile factories in the list, otherwise we die right here
        if len(self.profile_factories) == 0:
            raise ConfigError("no single profile factory configured, nothing to do")

    def start(self):
        self.do_stop = False
        self.server.start()
        Thread.start(self)

        if self.selftest_hammer is not None:
            self.selftest_hammer.start()

    def stop(self):
        # signal the controller thread to stop
        self.do_stop = True
        # tell the test hammer to stop as well
        if self.selftest_hammer:
            self.selftest_hammer.stop()

    def run(self):
        '''
        SSLCAuditCLI loop function. Will run until the desired number of clients is handled.
        '''
        logger.debug('entering main loop in run()')

        # loop until get all desired results, quit if stopped
        while not self.do_stop:
            try:
                # wait for a message blocking for short intervals, check stop flag frequently
                res = self.server.res_queue.get(True, self.queue_read_timeout)
                logger.debug("got result %s", res)
                self.event_handler(res)

                if isinstance(res, SessionEndResult):
                    if self.options.post_test_action == CFG_PTA_EXIT:
                        break
            except Empty:
                pass

        self.server.stop()
        if self.selftest_hammer:
            self.selftest_hammer.stop()
        logger.debug('exited main loop in run()')

    def init_self_tests(self):
        # determine where to connect to
        if self.options.listen_on[0] == HOST_ADDR_ANY:
            peer_host = 'localhost'
        else:
            peer_host = self.options.listen_on[0]
        peer = (peer_host, self.options.listen_on[1])

        # instantiate hammer class
        if self.options.self_test == 0:
            self.selftest_hammer = None
        else:
            if self.options.self_test == 1:
                self.selftest_hammer = TCPConnectionHammer(-1)

            elif self.options.self_test == 2:
                self.selftest_hammer = CNVerifyingSSLConnectionHammer(-1, 'hello')

            elif self.options.self_test == 3:
                if self.options.user_ca_cert_file is not None:
                    self.selftest_hammer = CurlHammer(-1, self.options.user_ca_cert_file)
                else:
                    raise ConfigError('test mode 3 requires --user-ca-cert/--user-ca-key')
            else:
                raise ConfigError('invalid selftest number %d' % self.options.self_test)

            # set the peer for the hammer
            self.selftest_hammer.set_peer(peer)
