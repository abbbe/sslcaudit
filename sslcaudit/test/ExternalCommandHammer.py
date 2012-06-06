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
            res = call(cmd, stdout = devnull, stderr = devnull, close_fds=True)
            self.logger.debug('exit code %d', res)
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
