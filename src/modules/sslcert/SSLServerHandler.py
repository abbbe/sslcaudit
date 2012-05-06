''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import M2Crypto, logging
from time import time
from M2Crypto.SSL.timeout import timeout
from src.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.modules.base.BaseServerHandler import BaseServerHandler

DEFAULT_SOCK_READ_TIMEOUT = 3.0
MAX_SIZE = 1024

# --- some classes and constants here should be moved elsewhere, to be shared between different modules

UNEXPECTED_EOF = 'unexpected eof'
ALERT_UNKNOWN_CA = 'tlsv1 alert unknown ca'
ALERT_CERT_UNKNOWN = 'sslv3 alert certificate unknown'

class Connected(object): pass

class ConnectedGotEOFBeforeTimeout(Connected):
    def __init__(self, dt=None):
        self.dt = dt

    def __str__(self):
        if self.dt != None:
            dt_str = " (in %.3fs)" % self.dt
        else:
            dt_str = ''
        return "connected, EOF before timeout%s" % dt_str

    def __eq__(self, other):
        # NB: ignore actual DT
        return self.__class__ == other.__class__


class ConnectedReadTimeout(Connected):
    def __init__(self, dt=None):
        self.dt = dt

    def __str__(self):
        if self.dt != None:
            dt_str = " (in %.1fs)" % self.dt
        else:
            dt_str = ''
        return "connected, read timeout%s" % dt_str

    def __eq__(self, other):
        # NB: ignore actual DT
        return self.__class__ == other.__class__


class ConnectedGotRequest(Connected):
    def __init__(self, req=None, dt=None):
        self.req = req
        self.dt = dt

    def __eq__(self, other):
        # NB: ignore actual DT
        if self.__class__ != other.__class__: return False

        return self.req == None or self.req == other.req

    def __str__(self):
        if self.dt != None:
            dt_str = '%.1fs' % self.dt
        else:
            dt_str = '?s'
        if self.req != None:
            noctets_str = '%d' % len(self.req)
        else:
            noctets_str = '?'
        return 'connected, got %s octets in %s' % (noctets_str, dt_str)

# ------------------

class SSLServerHandler(BaseServerHandler):
    '''
    This class implements SSL/TLS server. Its handle() method tries to perform SSL/TLS handshake using provided
    certificate and a key. If connection is successful, it waits for the client to send some data. In some cases
    even if SSL session is set up a client terminates the connection right away (for example if it realises CN does
    not match the expected value).
    '''
    logger = logging.getLogger('SSLServerHandler')

    sock_read_timeout = DEFAULT_SOCK_READ_TIMEOUT

    def __init__(self, proto):
        BaseServerHandler.__init__(self)

        self.proto = proto

    def handle(self, conn, profile):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert_chain(certchainfile=profile.certnkey.cert_filename, keyfile=profile.certnkey.key_filename)

        self.logger.debug('trying to accept SSL connection %s with profile %s', conn, profile)
        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.set_socket_read_timeout(timeout(self.sock_read_timeout))
            ssl_conn.setup_ssl()
            ssl_conn_res = ssl_conn.accept_ssl()
            if ssl_conn_res == 1:
                self.logger.debug('SSL connection accepted')
            else:
                self.logger.debug('SSL handshake failed: %s', ssl_conn.ssl_get_error(ssl_conn_res))
                res = ssl_conn.ssl_get_error(ssl_conn_res)
                return ClientConnectionAuditResult(conn, profile, res)

            # try to read something from the client
            start_time = time()
            client_req = ssl_conn.read(size=MAX_SIZE)
            end_time = time()
            dt = end_time - start_time

            if client_req == None:
                # read timeout
                res = ConnectedReadTimeout(dt)
            else:
                if len(client_req) == 0:
                    # EOF or timeout? XXX
                    if dt < self.sock_read_timeout:
                        res = ConnectedGotEOFBeforeTimeout(dt)
                    else:

                        res = ConnectedReadTimeout(dt)
                else:
                    # got data
                    res = ConnectedGotRequest(client_req, dt)
        except Exception as ex:
            res = ex.message
            self.logger.debug('SSL accept failed: %s', ex)

        # report the result

        return ClientConnectionAuditResult(conn, profile, res)

    def __repr__(self):
        return "SSLServerHandler%s" % self.__dict__
