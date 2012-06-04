# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import M2Crypto, logging
from time import time
from M2Crypto.SSL.timeout import timeout
from sslcaudit.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from sslcaudit.modules.base.BaseServerHandler import BaseServerHandler

DEFAULT_SOCK_READ_TIMEOUT = 3.0
MAX_SIZE = 1024

# --- some classes and constants here should be moved elsewhere, to be shared between different modules

UNEXPECTED_EOF = 'unexpected eof'
ALERT_UNKNOWN_CA = 'tlsv1 alert unknown ca'
ALERT_CERT_UNKNOWN = 'sslv3 alert certificate unknown'

class Connected(object):
    def __eq__(self, other):
        return self.__class__ == other.__class__

    def __hash__(self):
        return hash(self.__class__)

class ServerHandler(BaseServerHandler):
    '''
    This class implements SSL/TLS server. Its handle() method tries to perform SSL/TLS handshake using provided
    protocol and ciphers.
    '''
    logger = logging.getLogger('sslproto.ServerHandler')

    sock_read_timeout = DEFAULT_SOCK_READ_TIMEOUT

    def __init__(self):
        BaseServerHandler.__init__(self)

    def handle(self, conn, profile):
        ctx = M2Crypto.SSL.Context()
        ctx.load_cert_chain(certchainfile=profile.certnkey.cert_filename, keyfile=profile.certnkey.key_filename)
        #ctx.set_options(m2.SSL_OP_ALL | m2.SSL_OP_NO_SSLv2)
        ctx.set_cipher_list(profile.profile_spec.cipher)

        self.logger.debug('trying to accept SSL connection %s with profile %s', conn, profile)
        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.set_socket_read_timeout(timeout(self.sock_read_timeout))
            ssl_conn.setup_ssl()
            ssl_conn_res = ssl_conn.accept_ssl()
            if ssl_conn_res == 1:
                self.logger.debug('SSL connection accepted')
                return ClientConnectionAuditResult(conn, profile, Connected())
            else:
                self.logger.debug('SSL handshake failed: %s', ssl_conn.ssl_get_error(ssl_conn_res))
                res = ssl_conn.ssl_get_error(ssl_conn_res)
                return ClientConnectionAuditResult(conn, profile, res)

        except Exception as ex:
            res = ex.message
            self.logger.debug('SSL accept failed: %s', ex)

        return ClientConnectionAuditResult(conn, profile, res)

    def __repr__(self):
        return "sslproto.ServerHandler%s" % self.__dict__
