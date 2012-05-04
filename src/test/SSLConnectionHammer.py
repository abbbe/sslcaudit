''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import logging, M2Crypto
from src.test.Hammer import Hammer
from src.test.TCPConnectionHammer import TCPConnectionHammer

DEFAULT_VERIFY_MODE = M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert
DEFAULT_VERIFY_DEPTH = 9

class SSLConnectionHammer(Hammer):
    logger = logging.getLogger('SSLConnectionHammer')

    def __init__(self, ca_cert_file=None):
        TCPConnectionHammer.__init__(self)
        self.ca_cert_file = ca_cert_file

        # create a context
        self.ctx = M2Crypto.SSL.Context()

        if self.ca_cert_file == None:
            self.ctx.set_verify(M2Crypto.SSL.verify_none, depth=9)
            self.ctx.set_allow_unknown_ca(True)
        else:
            self.ctx.load_verify_locations(self.ca_cert_file)
            self.ctx.set_verify(DEFAULT_VERIFY_MODE, depth=DEFAULT_VERIFY_DEPTH, callback=self.verify_callback)

    def connect_l4(self, sock):
        self.logger.debug('starting SSL handshake')
        ssl_conn = M2Crypto.SSL.Connection(ctx=self.ctx, sock=sock)
        ssl_conn.setup_ssl()

        res = ssl_conn.connect_ssl()
        if res == 1:
            self.logger.debug('SSL handshake complete')
            return True
        else:
            self.logger.error('SSL handshake failed: %s', ssl_conn.ssl_get_error(res))
            return False

    def verify_callback(self):
        pass


class NotVerifyingSSLConnectionHammer(SSLConnectionHammer):
    '''
    This client completely ignores the content of server certificate.
    '''


class ChainVerifyingSSLConnectionHammer(SSLConnectionHammer):
    '''
    This client only matches CN
    '''

    def __init__(self, ca_cert_file):
        SSLConnectionHammer.__init__(self, ca_cert_file=ca_cert_file)
