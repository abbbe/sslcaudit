from src.ClientAuditor.ClientConnectionAuditResult import ClientConnectionAuditResult
from src.ClientAuditor.ClientConnectionAuditor import ClientConnectionAuditor

DEFAULT_X509_COMMON_NAME = "nonexistent.example.com"

class SelfSignedSSLClientConnectionAuditor(ClientConnectionAuditor):
    def __init__(self, x509_common_name=DEFAULT_X509_COMMON_NAME):
        self.x509_common_name = x509_common_name

    def handle(self, conn):
    #        ssl=SSL_new(ctx);
    #        SSL_set_bio(ssl,sbio,sbio);
    #        if((r=SSL_accept(ssl)<=0))
    #        berr_exit("SSL accept error");
        return ClientConnectionAuditResult(conn.get_client_id())
        #raise NotImplementedError()
