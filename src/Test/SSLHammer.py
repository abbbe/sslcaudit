import M2Crypto
from src.Test.TCPHammer import TCPHammer

class SSLHammer(TCPHammer):
    def __init__(self, peer, nattempts, verify):
        TCPHammer.__init__(self, peer, nattempts)
        self.verify = verify

    def connect_l4(self, sock):
        ctx = M2Crypto.SSL.Context()
        if self.verify:
            ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, depth=9)
        ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=sock)
        ssl_conn.setup_ssl()
        ssl_conn.connect_ssl()


class NotVerifyingSSLHammer(SSLHammer):
    def __init__(self, peer, nattempts):
        SSLHammer.__init__(self, peer, nattempts, verify=False)


class VerifyingSSLHammer(SSLHammer):
    def __init__(self, peer, nattempts):
        SSLHammer.__init__(self, peer, nattempts, verify=True)
