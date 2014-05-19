# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import M2Crypto, logging
from time import time
from M2Crypto.SSL.timeout import timeout
from sslcaudit.core.ConnectionAuditEvent import ConnectionAuditResult
from sslcaudit.modules.base.BaseServerHandler import BaseServerHandler
from sslcaudit.modules.sslproto import resolve_ssl_code
from sslcaudit.modules.sslproto import set_ephemeral_params
from M2Crypto import m2
from sslcaudit.modules.sslcert.SSLServerHandler import UNEXPECTED_EOF

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

    def __str__(self):
        return 'Connected()'


class ServerHandler(BaseServerHandler):
    '''
    This class implements SSL/TLS server. Its handle() method tries to perform SSL/TLS handshake using provided
    protocol and ciphers.
    '''
    logger = logging.getLogger('sslproto.ServerHandler')

    sock_read_timeout = DEFAULT_SOCK_READ_TIMEOUT

    def __init__(self):
        BaseServerHandler.__init__(self)

    def handle(self, conn, profile, file_bag):
        # create a context, explicitly specify the flavour of the protocol
        ctx = M2Crypto.SSL.Context(protocol=profile.profile_spec.proto, weak_crypto=True)
        ctx.load_cert_chain(certchainfile=profile.certnkey.cert_filename, keyfile=profile.certnkey.key_filename)
        set_ephemeral_params(ctx)

        # set restrict all protocols except the one prescribed by the profile
        options = m2.SSL_OP_ALL
        if profile.profile_spec.proto == 'sslv2':
            options |= m2.SSL_OP_NO_SSLv3 | m2.SSL_OP_NO_TLSv1
        elif profile.profile_spec.proto == 'sslv3':
            options |= m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_TLSv1
        elif profile.profile_spec.proto == 'tlsv1':
            options |= m2.SSL_OP_NO_SSLv2 | m2.SSL_OP_NO_SSLv3
        else:
            raise ValueError('unsupported protocol: %s' % profile.profile_spec.proto)
        ctx.set_options(options)

        # set allowed ciphers
        ctx.set_cipher_list(profile.profile_spec.cipher)

        self.logger.debug('trying to accept SSL connection %s with profile %s', conn, profile)
        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.set_socket_read_timeout(timeout(self.sock_read_timeout))
            ssl_conn.setup_ssl()
            ssl_conn_res = ssl_conn.accept_ssl()
            if ssl_conn_res == 1:
                self.logger.debug(
                    'SSL connection accepted, version %s cipher %s' % (ssl_conn.get_version(), ssl_conn.get_cipher()))
                if ssl_conn.get_version() == 'SSLv2' and ssl_conn.get_cipher() is None:
                    # workaround for #46
                    raise Exception(UNEXPECTED_EOF)
                return ConnectionAuditResult(conn, profile, Connected())
            else:
                res = ssl_conn.ssl_get_error(ssl_conn_res)
                res = resolve_ssl_code(res)
                self.logger.debug('SSL handshake failed: %s', res)
                return ConnectionAuditResult(conn, profile, res)

        except Exception as ex:
            res = str(ex)
            self.logger.debug('SSL accept failed: %s', ex)

        return ConnectionAuditResult(conn, profile, res)

    def __repr__(self):
        return "sslproto.ServerHandler%s" % self.__dict__
