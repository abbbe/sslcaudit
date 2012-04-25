class ClientConnection(object):
    def __init__(self, sock, client_address):
        self.sock = sock
        self.client_address = client_address
        self.sockname = self.sock.getsockname()

    def get_client_id(self):
        '''
        This function returns a key is used to distinguish between different clients under test.
        In the current implementation we use client IP address as a key.
        '''
        return self.client_address[0]

    def __str__(self):
        return "%s [%s->%s]" % (self.get_client_id(), self.client_address, self.sockname)
