''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import M2Crypto
from src.test.TCPHammer import TCPHammer

class SSLHammer(TCPHammer):
    def __init__(self, name, ca_cert_file = None):
        TCPHammer.__init__(self, name)
        self.ca_cert_file = ca_cert_file

    def connect_l4(self, sock):
        self.ctx = M2Crypto.SSL.Context()
        if self.ca_cert_file != None:
            self.ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, depth=9)
            self.ctx.load_verify_locations(self.ca_cert_file)
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
        SSLHammer.__init__(self, name='NotVerifyingSSLHammer')


class ChainVerifyingSSLHammer(SSLHammer):
    '''
    This client only matches CN
    '''

    def __init__(self, ca_cert_file):
        SSLHammer.__init__(self, name='ChainVerifyingSSLHammer()', ca_cert_file=ca_cert_file)

        self.init_ssl(
            mode=M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert,
            depth=10,
            callback=self.verify_callback)

    def verify_callback(self):
        pass
