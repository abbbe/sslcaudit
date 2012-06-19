# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import logging
import os
from sslcaudit.test.ConnectionHammer import ConnectionHammer
from subprocess import call

class ExternalCommandHammer(ConnectionHammer):
    logger = logging.getLogger('ConnectionHammer')

    def __init__(self, nattempts, ca_cert_file=None):
        ConnectionHammer.__init__(self, nattempts)
        self.ca_cert_file = ca_cert_file

    def get_command(self):
        raise NotImplemented('subclasses must override this method')

    def hammer(self, _round):
        cmd = self.get_command()

        # run the command discarding stdout and stderr
        devnull = open(os.devnull, 'w')
        try:
            self.logger.debug('calling %s', str(cmd))
            res = call(cmd, stdout=devnull, stderr=devnull, close_fds=True)
            self.logger.debug('exit code %d', res)
        except OSError as ex:
            print 'failed to call %s, exceptin %s' % (cmd, ex)
            raise ex
        finally:
            devnull.close()


class CurlHammer(ExternalCommandHammer):
    logger = logging.getLogger('CurlHammer')

    def get_command(self):
        server_url = 'https://%s:%d' % (self.peer[0], self.peer[1])
        if self.ca_cert_file:
            return ['curl', '--cacert', self.ca_cert_file, server_url]
        else:
            return ['curl', server_url]

#OPENSSL_PROG = 'openssl-1.0.1b/apps/openssl'
OPENSSL_PROG = 'openssl'

class OpenSSLHammer(ExternalCommandHammer):
    logger = logging.getLogger('OpenSSLHammer')
    def __init__(self, nattempts, openssl_args):
        ExternalCommandHammer.__init__(self, nattempts)
        self.openssl_args = openssl_args

    def get_command(self):
        assert not self.ca_cert_file

        server_n_port = '%s:%d' % (self.peer[0], self.peer[1])
        return [
            OPENSSL_PROG, 's_client',
            '-connect', server_n_port,
            '-cipher', 'ALL'
        ].extend(self.openssl_args)
