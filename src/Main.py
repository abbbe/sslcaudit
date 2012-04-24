import logging, sys
from optparse import OptionParser
from threading import Thread
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.ClientAuditor.SSL.SSLClientAuditorSet import SSLClientAuditorSet

DEFAULT_PORT = 8443
SSLCERT_MODULE_NAME = 'sslcert'
DUMMY_MODULE_NAME = 'dummy'

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Main')

class Main(Thread):
    def __init__(self, argv):
        Thread.__init__(self, target=self.run)

        parser = OptionParser(usage="sslcaudit ", version="sslcaudit 0.1")
        parser.add_option("-l", dest="listen_addr", default='0.0.0.0', help="Listening port")
        parser.add_option("-p", dest="listen_port", default=DEFAULT_PORT, help="Listening port")
        parser.add_option("-m", dest="module", default=SSLCERT_MODULE_NAME, help="Listening port")
        parser.add_option("-s", dest="server", help="Server host:port")
        parser.add_option("-d", action='store_true', dest="debug", help="Enable debugging")
        parser.add_option("-n", dest="nclients", default=1, help="Number of clients to handle before quitting")
        (options, args) = parser.parse_args(argv)

        if len(args) > 0:
            parser.error("too many arguments")

        self.options = options

        if self.options.debug:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.DEBUG) ## XXX INFO

        module_args = {}
        if self.options.server != None:
            module_args['server'] = self.options.server

        if self.options.module == SSLCERT_MODULE_NAME:
            self.auditor_set = SSLClientAuditorSet(module_args)
        elif self.options.module == DUMMY_MODULE_NAME:
            self.auditor_set = DummyClientAuditorSet(module_args)
        else:
            raise Exception("auditor module must be specified")

        self.server = ClientAuditorServer((self.options.listen_addr, self.options.listen_port), self.auditor_set)

    def start(self):
        self.server.start()
        Thread.start(self)

    def handle_result(self, res):
        pass

    def run(self):
        '''
        Main loop function. Will run until the desired number of clients is handled.
        '''
        nresults = 0
        while nresults < self.options.nclients:
            res = self.server.res_queue.get()
            logger.debug("got result %s", res)
            self.handle_result(res)

            if isinstance(res, ClientAuditResult):
                nresults = nresults + 1

if __name__ == "__main__":
    main = Main(sys.argv[1:])
    main.start()
    main.join()
