''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import M2Crypto
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor

UNKNOWN_CA = 'tlsv1 alert unknown ca'
UNEXPECTED_EOF = 'unexpected eof'
CONNECTED = 'connected'

MODULE_ID = 'sslcert' # XXX duplication

READ_TIMEOUT = 3
MAX_SIZE = 1024

class Connected:
    def __init__(self, client_req = None):
        self.client_req_size = client_req

    def __str__(self):
        if self.client_req_size == None:
            noctets = 0
        else:
            noctets = len(self.client_req_size)
        return "connected, got %d octets" % noctets

class SSLClientConnectionAuditor(ClientConnectionAuditor):
    def __init__(self, proto, certnkey):
        self.proto = proto
        self.certnkey = certnkey
        name = '%s(%s)' % (MODULE_ID, self.certnkey.name)
        ClientConnectionAuditor.__init__(self, name)

    def handle(self, conn):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert(certfile=self.certnkey.cert_filename, keyfile=self.certnkey.key_filename)

        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            #ssl_conn.set_socket_read_timeout(READ_TIMEOUT)
            ssl_conn.setup_ssl()
            ssl_conn.accept_ssl()

            # try to read something from the client
            #client_req = ssl_conn.read(size=MAX_SIZE)
            #es = Connected(client_req)
            res = CONNECTED
        except Exception as ex:
            res = ex.message

        # report the result
        return ClientConnectionAuditResult(self, conn, res)

    def __repr__(self):
        return "SSLClientConnectionAuditor%s" % self.__dict__

