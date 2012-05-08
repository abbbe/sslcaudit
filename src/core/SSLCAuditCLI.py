''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging
from optparse import OptionParser
from src.core.BaseClientAuditController import BaseClientAuditController, PROG_NAME, PROG_VERSION, HOST_ADDR_ANY
from src.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.core.ConfigErrorException import ConfigErrorException

FORMAT = '%(asctime)s %(name)s %(levelname)s   %(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT)

logger = logging.getLogger('SSLCAuditCLI')

DEFAULT_HOST = HOST_ADDR_ANY
DEFAULT_PORT = 8443
DEFAULT_MODULES = 'sslcert'
DEFAULT_LISTEN_ON = '%s:%d' % (DEFAULT_HOST, DEFAULT_PORT)
OUTPUT_FIELD_SEPARATOR = ' '

class SSLCAuditCLI(BaseClientAuditController):
    def __init__(self, argv):
        BaseClientAuditController.__init__(self, self.parse_options(argv))

    def parse_options(self, argv):
        parser = OptionParser(usage=('%s [OPTIONS]' % PROG_NAME), version=("%s %s" % (PROG_NAME, PROG_VERSION)))
        parser.add_option("-l", dest="listen_on", default=DEFAULT_LISTEN_ON,
            help='Specify IP address and TCP PORT to listen on, in format of [HOST:]PORT. '
            + 'Default is %s' % DEFAULT_LISTEN_ON)
        parser.add_option("-m", dest="modules", default=DEFAULT_MODULES,
            help="Launch specific modules. For now the only functional module is 'sslcert'. "
                 + "There is also 'dummy' module used for internal testing or as a template code for "
            + "new modules. Default is %s" % DEFAULT_MODULES)
        parser.add_option("-v", dest="verbose", default=0,
            help="Increase verbosity level. Default is 0. Try 1.")
        parser.add_option("-d", dest="debug_level", default=0,
            help="Set debug level. Default is 0, which disables debugging output. Try 1 to enable it.")
        parser.add_option("-c", dest="nclients", default=1,
            help="Number of clients to handle before quitting. By default sslcaudit will quit as soon as "
            + "it gets one client fully processed.")
        parser.add_option("-N", dest="test_name",
            help="Set the name of the test. If specified will appear in the leftmost column in the output.")
        parser.add_option('-T', type='int', dest='self_test',
            help='Launch self-test. 0 - plain TCP client, 1 - CN verifying client, 2 - curl.')

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
            help=("Do not use default CN"))
        parser.add_option("--no-self-signed", action="store_true", default=False, dest="no_self_signed",
            help="Don't try self-signed certificates")
        parser.add_option("--no-user-cert-signed", action="store_true", default=False, dest="no_user_cert_signed",
            help="Do not sign server certificates with user-supplied one")

        (options, args) = parser.parse_args(argv)
        if len(args) > 0:
            raise ConfigErrorException("unexpected arguments: %s" % args)

        # transform listen_on string into a tuple
        listen_on_parts = options.listen_on.split(':')
        if len(listen_on_parts) == 1:
            # convert "PORT" string to (DEFAULT_HOST, POST) tuple
            options.listen_on_addr = DEFAULT_HOST
            options.listen_on_port = int(listen_on_parts[0])
        elif len(listen_on_parts) == 2:
            # convert "HOST:PORT" string to (HOST, PORT) tuple
            options.listen_on_addr = listen_on_parts[0]
            options.listen_on_port = int(listen_on_parts[1])
        else:
            raise ConfigErrorException("invalid value for -l parameter '%s'" % self.options.listen_on.split(':'))
        options.listen_on = (options.listen_on_addr, options.listen_on_port)

        return options

    def run(self):
        '''
        Print config info to the console before running the controller
        '''
        if self.options.verbose > 0:
            print '# filebag location: %s' % str(self.file_bag.base_dir)
        BaseClientAuditController.run(self)

    def handle_result(self, res):
        if isinstance(res, ClientConnectionAuditResult):
            # dump:
            # * filebag path (only in verbose mode),
            # * client address and port,
            # * server profile
            # * result
            # all in one line, in fixed width columns
            fields = []
            client_address = '%s:%d' % (res.conn.client_address)
            fields.append('%-16s' % client_address)
            fields.append('%-60s' % (res.profile))
            fields.append(str(res.res))
            print OUTPUT_FIELD_SEPARATOR.join(fields)
