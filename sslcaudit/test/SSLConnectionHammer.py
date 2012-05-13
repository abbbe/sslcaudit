''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import time, logging, M2Crypto
from M2Crypto.SSL.Checker import  SSLVerificationError
from sslcaudit.test.ConnectionHammer import ConnectionHammer

class CNVerifyingSSLConnectionHammer(ConnectionHammer):
    '''
    This client only matches CN
    '''
    logger = logging.getLogger('CNVerifyingSSLConnectionHammer')

    def __init__(self, nattempts, hello):
        ConnectionHammer.__init__(self, nattempts)
        self.hello = hello

        # create a context
        self.ctx = M2Crypto.SSL.Context()
        self.ctx.set_allow_unknown_ca(True)
        self.ctx.set_verify(M2Crypto.SSL.verify_none, 9)

    def hammer(self, i):
        self.logger.debug('starting SSL handshake')
        conn = M2Crypto.SSL.Connection(self.ctx)

        try:
            res = conn.connect(self.peer)
            if res == 1:
                conn.write(self.hello)
                self.logger.debug('SSL handshake complete for connection %d to %s, hello sent, waiting for %.1fs before closing',
                    i, self.peer, self.delay_before_close)
                time.sleep(self.delay_before_close)
                conn.close()
                self.logger.debug('SSL connection %d to %s closed', i, self.peer)
                return True
            else:
                self.logger.debug('SSL handshake failed: %s', ssl_conn.ssl_get_error(res))
                return False
        except SSLVerificationError as ex:
            self.logger.debug('SSL handshake SSLVerificationError: %s', ex)
            return False

class ChainVerifyingSSLConnectionHammer(CNVerifyingSSLConnectionHammer):
    '''
    This client only matches CN and verifies the chain of trust
    '''
    logger = logging.getLogger('ChainVerifyingSSLConnectionHammer')

    def __init__(self, nattempts, hello, ca_cert_file):
        CNVerifyingSSLConnectionHammer.__init__(self, nattempts, hello)
        self.ca_cert_file = ca_cert_file

        #self.ctx.set_allow_unknown_ca(True)
        self.ctx.load_verify_locations(self.ca_cert_file)
        self.ctx.set_verify(
            mode=M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert,
            depth=9,
            callback=self.verify_callback)

        self.logger.info('initialized with ca_cert_file %s' % self.ca_cert_file)

    def verify_callback(self):
        #self.logger.info('*** verify_callback called ***')
        pass
