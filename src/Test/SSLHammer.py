import M2Crypto
from src.Test.TCPHammer import TCPHammer

class SSLHammer(TCPHammer):
    def __init__(self, verify):
        TCPHammer.__init__(self)
        self.verify = verify

    def connect_l4(self, sock):
        self.ctx = M2Crypto.SSL.Context()
        if self.verify:
            self.ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, depth=9)
        ssl_conn = M2Crypto.SSL.Connection(ctx=self.ctx, sock=sock)
        ssl_conn.setup_ssl()
        ssl_conn.connect_ssl()

        self.ctx.set_verify(self.mode, self.depth, self.callback)
        self.verify()

    def init_ssl(self, mode, depth, callback):
        self.mode = mode
        self.depth = depth
        self.callback = callback


class NotVerifyingSSLHammer(SSLHammer):
    '''
    This client completely ignores the content of server certificate.
    '''
    def __init__(self):
        SSLHammer.__init__(self, verify=False)


class VerifyingSSLHammer(SSLHammer):
    '''
    This client does proper verification of server certificate.
    '''
    def __init__(self):
        SSLHammer.__init__(self, verify=True)

class VerifyingSSLHammer(SSLHammer):
    '''
    This client only matches CN
    '''
    def __init__(self, cn):
        SSLHammer.__init__(self, verify=True)
        self.cn = cn

        self.init_ssl(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, 10, self.verify_callback)

    def verify_callback(self):
            pass
