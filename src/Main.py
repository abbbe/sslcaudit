''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from Queue import Empty
import logging, sys
from optparse import OptionParser
from threading import Thread
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.ClientAuditor.SSL.SSLClientAuditorSet import SSLClientAuditorSet, DEFAULT_CN

DEFAULT_PORT = 8443
SSLCERT_MODULE_NAME = 'sslcert'
DUMMY_MODULE_NAME = 'dummy'

class Main(Thread):
    logger = logging.getLogger('Main')

    def __init__(self, argv):
        Thread.__init__(self, target=self.run)

        parser = OptionParser(usage="sslcaudit ", version="sslcaudit 0.1")
        parser.add_option("-l", dest="listen_addr", default='0.0.0.0', help="Listening port")
        parser.add_option("-p", dest="listen_port", default=DEFAULT_PORT, help="Listening port")
        parser.add_option("-m", dest="module", default=SSLCERT_MODULE_NAME, help="Audit module (sslcert by default)")
        parser.add_option("-d", dest="debug_level", default=0, help="Debug level")
        parser.add_option("-c", dest="nclients", default=1, help="Number of clients to handle before quitting")
        parser.add_option("-N", dest="test_name", help="User-specified name of the test")

        parser.add_option("--no-default-cn", action="store_true", default=False, dest="no_default_cn",
            help=("Do not use default CN (%s)" % (DEFAULT_CN)))
        parser.add_option("--user-cn", dest="user_cn",
            help="Use specified CN")
        parser.add_option("--server", dest="server",
            help="HOST:PORT to fetch the certificate from")
        parser.add_option("--user-cert", dest="user_cert_file",
            help="A file with user-supplied certificate")
        parser.add_option("--user-key", dest="user_key_file",
            help="A file with user-supplied key")

        parser.add_option("--no-self-signed", action="store_true", default=False, dest="no_self_signed",
            help="Don't try self-signed certificates")
        parser.add_option("--no-cert-signed", action="store_true", default=False, dest="no_cert_signed",
            help="Do not sign server certificates with user-supplied one")
        parser.add_option("--user-ca-cert", dest="user_ca_cert_file",
            help="A file with a cert for CA, useful for testing sslcaudit itself")
        parser.add_option("--user-ca-key", dest="user_ca_key_file",
            help="A file with a key for CA, useful for testing sslcaudit itself")

        (options, args) = parser.parse_args(argv)

        if len(args) > 0:
            parser.error("too many arguments")

        self.options = options

        logging.getLogger().setLevel(logging.INFO)
        if self.options.debug_level > 0:
            logging.getLogger('Main').setLevel(logging.DEBUG)
            logging.getLogger('ClientAuditorServer').setLevel(logging.DEBUG)

        if self.options.module == SSLCERT_MODULE_NAME:
            self.auditor_set = SSLClientAuditorSet(SSLCERT_MODULE_NAME, self.options)
        elif self.options.module == DUMMY_MODULE_NAME:
            self.auditor_set = DummyClientAuditorSet(self.options)
        else:
            raise Exception("auditor module must be specified")

        self.server = ClientAuditorServer((self.options.listen_addr, self.options.listen_port), self.auditor_set)
        self.queue_read_timeout = 0.1

    def start(self):
        self.do_stop = False
        self.server.start()
        Thread.start(self)

    def stop(self):
        # signal the thread to stop
        self.do_stop = True


    def handle_result(self, res):
        if isinstance(res, ClientConnectionAuditResult):
            print "%s" % (res)

    def run(self):
        '''
        Main loop function. Will run until the desired number of clients is handled.
        '''
        print "# %s" % self.options.test_name

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

        # print an empty line after all
        print

if __name__ == "__main__":
    main = Main(sys.argv[1:])
    main.start()
    main.join()
