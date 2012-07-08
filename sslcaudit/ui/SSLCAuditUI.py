# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

from exceptions import ValueError
from optparse import OptionParser
from sslcaudit.core import Utils, CFG_PTA_REPEAT, CFG_PTA_DROP, CFG_PTA_EXIT
from sslcaudit.core.BaseClientAuditController import PROG_NAME, PROG_VERSION
from sslcaudit.core.ConfigError import ConfigError
from sslcaudit.ui.SSLCAuditCLI import DEFAULT_LISTEN_ON, DEFAULT_MODULES

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
    parser.add_option("-q", action="store_true", dest="quiet", default=False,
        help="Quiet mode of operations, only display warnings and errors.")
    parser.add_option("-d", type='int', dest="debug_level", default=0,
        help="Set debug level. Default is 0, which disables debugging output. Try 1 to enable it.")
#    parser.add_option("-c", type='int', dest="nclients", default=1,
#        help="Number of clients to handle before quitting. By default sslcaudit will quit as soon as "
#        + "it gets one client fully processed.")
    parser.add_option("-a", dest="post_test_action", default=CFG_PTA_EXIT,
        help="Post-test action: '%s', '%s', '%s' (default)." % (CFG_PTA_REPEAT, CFG_PTA_DROP, CFG_PTA_EXIT))
    parser.add_option("-N", dest="test_name",
        help="Set the name of the test. If specified will appear in the leftmost column in the output.")
    parser.add_option('-T', type='int', dest='self_test', default=0,
        help='Launch self-test. 1 - plain TCP client, 2 - CN verifying client, 3 - curl (requires --user-ca-cert/key).')

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
        help=("Do not use default CN."))
    parser.add_option("--no-self-signed", action="store_true", default=False, dest="no_self_signed",
        help="Don't try self-signed certificates.")
    parser.add_option("--no-user-cert-signed", action="store_true", default=False, dest="no_user_cert_signed",
        help="Do not sign server certificates with the user-supplied one.")

#    parser.add_option("--iterate-suites", dest="iterate_suites", action="store_true", default=False,
#        help="Iterate through protocol cipher suites.")
    parser.add_option("--protocols", dest="protocols",
        help="A comma-separated list of SSL protocols (sslv2, sslv3, tlsv1). If not specified, all protocols are used.")
    # XXX the next statement contains a hardcoded list of ciphers. ideally should fetch it from sslproto module,
    # but this will introduce an unwanted dependency here. not sure how to do it properly.
    parser.add_option("--ciphers", dest="ciphers",
        help="Comma-separated list of ciphers to try. OpenSSL-style cipher string specification is supported. "
        "Default: HIGH:MEDIUM:LOW:EXPORT. Specify 'ITERATE' for built-in long list of ciphers, per protocol.")

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

    if ((options.post_test_action != CFG_PTA_REPEAT) and
        (options.post_test_action != CFG_PTA_DROP) and
        (options.post_test_action != CFG_PTA_EXIT)):
        raise ConfigError('invalid value for post-test-action (-a) parameter, accepted values: %s, %s, and %s'
        % (CFG_PTA_REPEAT, CFG_PTA_DROP, CFG_PTA_EXIT))

    return options
