''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
from SocketServer import TCPServer

#class ClientAuditorTCPServer(ThreadingMixIn, TCPServer):
class ThreadingTCPServer(TCPServer):
    '''
    This class extends TCPServer to enforce address reuse, enforce daemon threads, and allow threading.
    '''

    def __init__(self, listen_on):
        TCPServer.__init__(self, listen_on, None, bind_and_activate=False)
        self.daemon_threads = True
        # make sure SO_REUSE_ADDR socket option is set
        self.allow_reuse_address = True

        try:
            self.server_bind()
        except socket.error as ex:
            raise RuntimeError('failed to bind to %s, exception: %s' % (listen_on, ex))

        self.server_activate()