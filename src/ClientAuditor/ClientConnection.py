__author__ = 'abb'

class ClientConnection(object):
    def __init__(self, sock):
        self.sock = sock

    def get_id(self):
        '''
        This function returns a session key for a given socket. A key is used to distinguish
        between different clients under test. In the current implementation we use client IP
        address as a key.
        '''
        return self.sock.getpeername()[0]