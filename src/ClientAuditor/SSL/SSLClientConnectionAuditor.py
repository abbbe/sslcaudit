''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
import M2Crypto
from src.ClientAuditor.ClientConnectionAuditEvent import ClientConnectionAuditResult, PositiveAuditResult, NegativeAuditResult
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor

class SSLClientConnectionAuditor(ClientConnectionAuditor):
    def __init__(self, name, descr, proto, certnkey, expect_failure):
        ClientConnectionAuditor.__init__(self, name)
        self.descr = descr
        self.proto = proto
        self.certnkey = certnkey
        self.expect_failure = expect_failure

    def __str__(self):
        return "%s(%r, %r, %r)", str((self.name, self.descr, self.proto, self.certnkey.name, self.expect_failure))

    def handle(self, conn):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert(certfile=self.certnkey.cert_filename, keyfile=self.certnkey.key_filename)

        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.setup_ssl()
            ssl_conn.accept_ssl()

            actual_res = None
        except Exception as ex:
            actual_res = ex.message

        # report the result
        if actual_res == self.expect_failure:
            # the test does not fail or fails as expected
            return ClientConnectionAuditResult(self.name, conn.get_client_id(),
                PositiveAuditResult(actual_res))
        else:
            # the test fails not like expected or does not fail while it was expected to
            return ClientConnectionAuditResult(self.name, conn.get_client_id(),
                NegativeAuditResult(actual_res, self.expect_failure))
