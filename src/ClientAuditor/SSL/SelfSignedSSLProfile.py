from src.ClientAuditor.ClientAuditorProfile import ClientAuditorProfile

DEFAULT_X509_COMMON_NAME = "nonexistent.example.com"

class SelfSignedSSLProfile(ClientAuditorProfile):
    def __init__(self, x509_common_name=DEFAULT_X509_COMMON_NAME):
        self.x509_common_name = x509_common_name

    def handle(self, request):
    #        ssl=SSL_new(ctx);
    #        SSL_set_bio(ssl,sbio,sbio);
    #        if((r=SSL_accept(ssl)<=0))
    #        berr_exit("SSL accept error");
        raise NotImplementedError()
