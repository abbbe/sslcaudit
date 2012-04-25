from src.CertUtils import mk_selfsigned_replica_certnkey, grab_server_cert
from src.ClientAuditor.ClientAuditorSet import ClientAuditorSet
from src.ClientAuditor.SSL.SelfSignedSSLClientAuditor import SelfSignedSSLClientConnectionAuditor

DEFAULT_X509_SELFSIGNED_CERT_CN = "nonexistent.gremwell.com"

class SSLClientAuditorSet(ClientAuditorSet):
    def __init__(self, options):
        self.options = options

        # add auditor presenting an arbitrary self-signed certificate
        auditors = [SelfSignedSSLClientConnectionAuditor(cn = DEFAULT_X509_SELFSIGNED_CERT_CN)]

        if self.options.has_key('server'):
            # add auditor using a self-signed certificate mimicing a real server
            real_server_cert = grab_server_cert(self.options['server'])
            auditors.append(SelfSignedSSLClientConnectionAuditor(cert = real_server_cert))
        else:
            real_server_cert = None

        if self.options.has_key('common_name'):
            # fetch CN of the real server
            if real_server_cert != None:
                real_server_cn = real_server_cert.get_subject().x509_name.CN
            else:
                real_server_cn = None

            # check if user-supplied CN matches the one from the real server cert
            if real_server_cn != self.options.has_key('common_name'):
                # add auditor using a self-signed certificate with user-supplied CN
                auditors.append(SelfSignedSSLClientConnectionAuditor(cn = self.options.has_key('common_name')))

        ClientAuditorSet.__init__(self, auditors)
