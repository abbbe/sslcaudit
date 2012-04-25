import M2Crypto
from src.CertUtils import mk_simple_selfsigned_certnkey, mk_selfsigned_replica_certnkey
from src.ClientAuditor.ClientConnectionAuditEvent import PositiveAuditResult, NegativeAuditResult
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor

class SelfSignedSSLClientConnectionAuditor(ClientConnectionAuditor):
    def __init__(self, cn=None, cert=None, proto='sslv23'):
        if cn != None and cert == None:
            self.descr = "selfsigned cert1"
            self.init_by_cn(cn)
        elif cn == None and cert != None:
            self.descr = "selfsigned cert2"
            self.init_by_cert(cert)
        else:
            raise Exception("cn and cert parameters can't be provided simultaneously")

        self.proto = proto

    def init_by_cn(self, cn):
        certnkey = mk_simple_selfsigned_certnkey(cn=cn)
        self.init_by_certnkey(certnkey)

    def init_by_cert(self, cert):
        certnkey = mk_selfsigned_replica_certnkey(orig_cert=cert)
        self.init_by_certnkey(certnkey)

    def init_by_certnkey(self, certnkey):
        self.certnkey = certnkey

    def handle(self, conn):
        ctx = M2Crypto.SSL.Context(self.proto)
        ctx.load_cert(certfile=self.certnkey.cert_filename, keyfile=self.certnkey.key_filename)
        try:
            # try to accept SSL connection
            ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=conn.sock)
            ssl_conn.setup_ssl()
            ssl_conn.accept_ssl()

            # report success
            return PositiveAuditResult(self, conn.get_client_id(), 'MITM')
        except Exception as ex:
            return NegativeAuditResult(self, conn.get_client_id(), ex)

    def __str__(self):
        return "selfsigned,cn=%s" % (self.descr)