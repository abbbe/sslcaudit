from exceptions import ValueError
from optparse import OptionParser
from sslcaudit.core import Utils
from sslcaudit.core.BaseClientAuditController import PROG_NAME, PROG_VERSION
from sslcaudit.core.ConfigError import ConfigError
from sslcaudit.core.SSLCAuditCLI import DEFAULT_LISTEN_ON, DEFAULT_MODULES
import sslcaudit.core.Utils

__author__ = 'abb'

def parse_options(argv):
    '''
    This function takes command-line parameters as provided by OS and parses it into Python dictionary
    using OptionParser.
    '''
    parser = OptionParser(usage=('%s [OPTIONS]' % PROG_NAME), version=("%s %s" % (PROG_NAME, PROG_VERSION)))
    parser.add_option("-l", dest="listen_on", default=DEFAULT_LISTEN_ON,
        help='Specify IP address and TCP PORT to listen on, in format of HOST:PORT. '
        + 'Default is %s' % DEFAULT_LISTEN_ON)
    parser.add_option("-m", dest="modules", default=DEFAULT_MODULES,
        help="Launch specific modules. For now the only functional module is 'sslcert'. "
             + "There is also 'dummy' module used for internal testing or as a template code for "
        + "new modules. Default is %s" % DEFAULT_MODULES)
    parser.add_option("-g", dest="gui", action="store_true", default=False,
        help="Use graphical UI")
    parser.add_option("-v", type='int', dest="verbose", default=0,
        help="Increase verbosity level. Default is 0. Try 1.")
    parser.add_option("-d", type='int', dest="debug_level", default=0,
        help="Set debug level. Default is 0, which disables debugging output. Try 1 to enable it.")
    parser.add_option("-c", type='int', dest="nclients", default=1,
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
        raise ConfigError("unexpected arguments: %s" % args)

    # transform listen_on string into a tuple
    try:
        options.listen_on = Utils.parse_hostport(options.listen_on)
    except ValueError as ex:
        raise ConfigError("invalid value for -l parameter, exception: %s" % ex)

    # transform server string into a tuple
    if options.server is not None:
        try:
            options.server = Utils.parse_hostport(options.server)
        except ValueError as ex:
            raise ConfigError("invalid value for --server parameter, exception: %s" % ex)

    return options