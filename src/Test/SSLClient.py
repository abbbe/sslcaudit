import M2Crypto
from src.Test.TCPClient import TCPClient

class SSLClient(TCPClient):
    def __init__(self, peer, nattempts, verify):
        TCPClient.__init__(self, peer, nattempts)
        self.verify = verify

    def connect_l4(self, sock):
        ctx = M2Crypto.SSL.Context()
        if self.verify:
            ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, depth=9)
        ssl_conn = M2Crypto.SSL.Connection(ctx=ctx, sock=sock)
        ssl_conn.setup_ssl()
        ssl_conn.connect_ssl()


class NotVerifyingSSLClient(SSLClient):
    def __init__(self, peer, nattempts):
        SSLClient.__init__(self, peer, nattempts, verify=False)


class VerifyingSSLClient(SSLClient):
    def __init__(self, peer, nattempts):
        SSLClient.__init__(self, peer, nattempts, verify=True)
