import logging, sys
from optparse import OptionParser
from threading import Thread
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.ClientAuditor.SSL.SSLClientAuditorSet import SSLClientAuditorSet

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
        parser.add_option("-n", dest="nclients", default=1, help="Number of clients to handle before quitting")

        parser.add_option("--no-default-cn", action="store_true", dest="no_default_cn", help=("Do not use default CN(%s)" % ('XXX')))
        parser.add_option("--cn", dest="cn", help="")
        parser.add_option("--server", dest="server", help="HOST:PORT to fetch the certificate from")
        parser.add_option("--usercert", dest="usercert_file", help="A file with user-supplied certificate and private key")
        parser.add_option("--no-self-signed", dest="no_self_signed", help="Don't try self-signed certificates")
        parser.add_option("--no-usercert-signed", dest="no_usercert_signed", help="Do not sign server certificates with user-supplied one")
        parser.add_option("--good-cacert", dest="good_cacert_file", help="A file with cert/key for known good CA, useful for testing sslcaudit itself")

        (options, args) = parser.parse_args(argv)

        if len(args) > 0:
            parser.error("too many arguments")

        self.options = options

        logging.getLogger().setLevel(logging.INFO)
        if self.options.debug_level > 0:
            logging.getLogger('Main').setLevel(logging.DEBUG)
            logging.getLogger('ClientAuditorServer').setLevel(logging.DEBUG)

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
        if isinstance(res, ClientConnectionAuditResult):
            print res.client_id, res.auditor, res.details

    def run(self):
        '''
        Main loop function. Will run until the desired number of clients is handled.
        '''
        nresults = 0
        while nresults < self.options.nclients:
            res = self.server.res_queue.get()
            self.logger.debug("got result %s", res)
            self.handle_result(res)

            if isinstance(res, ClientAuditResult):
                nresults = nresults + 1

if __name__ == "__main__":
    main = Main(sys.argv[1:])
    main.start()
    main.join()
