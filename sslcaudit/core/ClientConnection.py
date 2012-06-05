# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

class ClientConnection(object):
    def __init__(self, sock, client_address):
        self.sock = sock
        self.client_address = client_address
        self.sockname = self.sock.getsockname()

    def get_session_id(self):
        '''
        This function returns a key is used to distinguish between different sessions between clients and servers.
        In the current implementation we use client IP address as a key.
        '''
        return self.client_address[0]

    def __str__(self):
        return "%s [%s->%s]" % (self.get_session_id(), self.client_address, self.sockname)
