''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import M2Crypto
from ovs.reconnect import CONNECT
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor

class SSLClientConnectionAuditor(ClientConnectionAuditor):
    def __init__(self, proto, certnkey):
        self.proto = proto
        self.certnkey = certnkey
        ClientConnectionAuditor.__init__(self, self.certnkey.name)

    def __str__(self):
        return "%s %s" % (self.proto, self.name)

    def handle(self, conn):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert(certfile=self.certnkey.cert_filename, keyfile=self.certnkey.key_filename)

        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.setup_ssl()
            ssl_conn.accept_ssl()

            res = CONNECT
        except Exception as ex:
            res = ex.message

        # report the result
        return ClientConnectionAuditResult(self, conn, res)

    def __repr__(self):
        return "SSLClientConnectionAuditor%s" % self.__dict__

    def __str__(self):
        return self.certnkey.name
