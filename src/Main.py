''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from Queue import Empty
import logging
from optparse import OptionParser
from threading import Thread
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.ClientHandler import ClientAuditResult
from src.modules.dummy.DummyClientAuditorSet import DummyClientAuditorSet
from src.modules.sslcert.SSLClientAuditorSet import SSLClientAuditorSet, DEFAULT_CN
from src.ConfigErrorException import ConfigErrorException

logger = logging.getLogger('Main')

DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = '8443'

PROG_NAME = 'sslcaudit'
PROG_VERSION = '1.0rc1'

OUTPUT_FIELD_SEPARATOR = ' '

class Main(Thread):
    def __init__(self, argv):
        Thread.__init__(self, target=self.run)

        self.init_options(argv)

        if self.options.debug_level > 0:
            logging.getLogger().setLevel(logging.DEBUG)

        self.init_modules()

        self.server = ClientAuditorServer(self.listen_on, self.auditor_sets)
        self.queue_read_timeout = 0.1

    def init_options(self, argv):
        parser = OptionParser(usage=('%s [OPTIONS]' % PROG_NAME), version=("%s %s" % (PROG_NAME, PROG_VERSION)))
        parser.add_option("-l", dest="listen_on", default='0.0.0.0:8443',
            help="Specify IP address and TCP PORT to listen on, in format of [HOST:]PORT")
        parser.add_option("-m", dest="module",
            help="Launch specific audit module. For now the only functional module is 'sslcert'. "
                 + "There is also 'dummy' module used for internal testing or as a template code for "
            + "new modules. By default 'sslcert' is started.")
        parser.add_option("-d", dest="debug_level", default=0,
            help="Set debug level. Default is 0, which disables debugging output. Try 1 to enable it.")
        parser.add_option("-c", dest="nclients", default=1,
            help="Number of clients to handle before quitting. By default sslcaudit will quit as soon as "
            + "it gets one client fully processed.")
        parser.add_option("-N", dest="test_name",
            help="Set the name of the test. If specified will appear in the leftmost column in the output.")

        parser.add_option("--user-cn", dest="user_cn",
            help="Set user-specified CN.")
        parser.add_option("--server", dest="server",
            help="Where to fetch the server certificate from, in HOST:PORT format.")
        parser.add_option("--user-cert", dest="user_cert_file",
            help="Set path to file containing the user-supplied certificate.")
        parser.add_option("--user-key", dest="user_key_file",
            help="Set path to file containing the user-supplied key.")
        parser.add_option("--user-ca-cert", dest="user_ca_cert_file",
            help="Set path to file containing certificate for user-supplied CA.")
        parser.add_option("--user-ca-key", dest="user_ca_key_file",
            help="Set path to file containing key for user-supplied CA.")

        parser.add_option("--no-default-cn", action="store_true", default=False, dest="no_default_cn",
            help=("Do not use default CN (%s)" % (DEFAULT_CN)))
        parser.add_option("--no-self-signed", action="store_true", default=False, dest="no_self_signed",
            help="Don't try self-signed certificates")
        parser.add_option("--no-user-cert-signed", action="store_true", default=False, dest="no_user_cert_signed",
            help="Do not sign server certificates with user-supplied one")

        (options, args) = parser.parse_args(argv)
        if len(args) > 0:
            raise ConfigErrorException("unexpected arguments: %s" % args)

        self.options = options

        # transform listen_on string into a tuple
        listen_on_parts = self.options.listen_on.split(':')
        if len(listen_on_parts) == 1:
            # convert "PORT" string to (DEFAULT_HOST, POST) tuple
            self.listen_on = (DEFAULT_HOST, int(listen_on_parts[0]))
        elif len(listen_on_parts) == 2:
            # convert "HOST:PORT" string to (HOST, PORT) tuple
            self.listen_on = (listen_on_parts[0], int(listen_on_parts[1]))
        else:
            raise ConfigErrorException("invalid value for -l parameter '%s'" % self.options.listen_on.split(':'))

    def init_modules(self):
        self.auditor_sets = []

        # load sslcert module by default or if specified explicitly
        if self.options.module == None or self.options.module == SSLClientAuditorSet.MODULE_ID:
            self.auditor_sets.append(SSLClientAuditorSet(self.options))

        # only use dummy module if it is specified explicitly
        if self.options.module == DummyClientAuditorSet.MODULE_ID:
            self.auditor_sets.append(DummyClientAuditorSet(self.options))

        # there must be some auditors in the list
        if len(self.auditor_sets) == 0:
            raise ConfigErrorException("auditor set is empty, nothing to do")

    def start(self):
        self.do_stop = False
        self.server.start()
        Thread.start(self)

    def stop(self):
        # signal the thread to stop
        self.do_stop = True

    def handle_result(self, res):
        if isinstance(res, ClientConnectionAuditResult):
            # print test name, client address and port, auditor name, and result
            # all in one line, in fixed width columns
            fields = []
            if self.options.test_name != None:
                fields.append('%-25s' % str(self.options.test_name))
            client_address = '%s:%d' % (res.conn.client_address)
            fields.append('%-16s' % client_address)
            fields.append('%-60s' % str(res.auditor.name))
            fields.append(str(res.res))
            print OUTPUT_FIELD_SEPARATOR.join(fields)

    def run(self):
        '''
        Main loop function. Will run until the desired number of clients is handled.
        '''
        nresults = 0
        # loop until get all desired results, quit if stopped
        while nresults < self.options.nclients and not self.do_stop:
            try:
                # wait for a message blocking for short intervals, check stop flag frequently
                res = self.server.res_queue.get(True, self.queue_read_timeout)
                logger.debug("got result %s", res)
                self.handle_result(res)

                if isinstance(res, ClientAuditResult):
                    nresults = nresults + 1
            except Empty:
                pass
