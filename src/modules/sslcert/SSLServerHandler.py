''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
from time import time

import M2Crypto
from M2Crypto.SSL.timeout import timeout
from src.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.modules.base.BaseServerHandler import BaseServerHandler

READ_TIMEOUT = timeout(sec=3.0)
MAX_SIZE = 1024

# --- some classes and constants here should be moved elsewhere, to be shared between different modules

UNKNOWN_CA = 'tlsv1 alert unknown ca'
UNEXPECTED_EOF = 'unexpected eof'
CONNECTED = 'connected'

class Connected(object): pass


class ConnectedGotEOF(Connected):
    def __init__(self, dt):
        self.dt = dt

    def __str__(self):
        return "connected, got EOF after %.1fs" % self.dt

    def __eq__(self, other):
        return self.__class__ == other.__class__


class ConnectedReadTimeout(Connected):
    def __init__(self, dt):
        self.dt = dt

    def __str__(self):
        if self.dt != None:
            dt_str = "%.1fs" % self.dt
        else:
            dt_str = '?'
        return "connected, got nothing in %s" % dt_str

    def __eq__(self, other):
        return self.__class__ == other.__class__


class ConnectedGotRequest(Connected):
    def __init__(self, req, dt):
        self.req = req
        self.dt = dt

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.req == other.req

    def __str__(self):
        noctets = len(self.req)
        return "connected, got %d octets after %.1fs" % (noctets, self.dt)

# ------------------

class SSLServerHandler(BaseServerHandler):
    '''
    This class implements SSL/TLS server. Its handle() method tries to perform SSL/TLS handshake using provided
    certificate and a key. If connection is successful, it waits for the client to send some data. In some cases
    even if SSL session is set up a client terminates the connection right away (for example if it realises CN does
    not match the expected value).
    '''
    def __init__(self, proto):
        BaseServerHandler.__init__(self)

        self.proto = proto

    def handle(self, conn, profile):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert_chain(certchainfile=profile.certnkey.cert_filename, keyfile=profile.certnkey.key_filename)
        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.set_socket_read_timeout(READ_TIMEOUT)
            ssl_conn.setup_ssl()
            ssl_conn.accept_ssl()

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
                    # EOF
                    res = ConnectedGotEOF(dt)
                else:
                    # got data
                    res = ConnectedGotRequest(client_req, dt)
        except Exception as ex:
            res = ex.message

        # report the result

        return ClientConnectionAuditResult(conn, profile, res)

    def __repr__(self):
        return "SSLServerHandler%s" % self.__dict__