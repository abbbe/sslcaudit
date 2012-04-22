import logging
logger = logging.getLogger('SSLClientAuditServer')

from SocketServer import TCPServer, BaseRequestHandler

class ServerProfilePool(object):
    def __init__(self, server_profile_set):
        self.profiles = server_profile_set.get_profiles()

class ClientAuditSession(object):
    '''This class holds information about the progress and the results of the audit of a single client'''
    def __init__(self, client_host, profile_set):
        self.client_host = client_host
        self.profile_set_iterator = profile_set.__iter__()
        self.results = []

    def handle(self, sock):
        client_host = sock.getpeername()[0]
        if client_host != self.client_host:
            # sanity check
            raise Exception('client_host mismatch')

        logger.debug('handling request from %s (%s)', self.client_host, sock.getpeername())
        try:
            profile = self.profile_set_iterator.next()
            logger.debug('auditing client %s using profile %s', client_host, profile)
            res = profile.handle(sock)
            logger.debug('auditing client %s using profile %s resulted in %s', client_host, profile, res)
            self.results.append((profile, res))
        except StopIteration:
            logger.debug('profile pool is empty')
        sock.close()

class TCPClientAuditHandler(BaseRequestHandler):
    '''Incoming connection handler. Passes the request to an existing or new session.'''
    def handle(self):
        client_host = self.request.getpeername()[0]
        if not self.server.clients.has_key(client_host):
            logger.debug("new client %s", client_host)
            self.server.clients[client_host] = ClientAuditSession(client_host, self.server.profile_set)
        self.server.clients[client_host].handle(self.request)

class Server(TCPServer):
    def __init__(self, listen_on, profile_set):
        # create TCP listener with SO_REUSE_ADDR socket option
        TCPServer.__init__(self, listen_on, TCPClientAuditHandler, bind_and_activate=False)
        self.allow_reuse_address = True
        self.server_bind()
        self.server_activate()

        self.listen_on = listen_on
        self.clients = {}
        self.profile_set = profile_set

    def serve_forever(self):
        logger.debug("starting serve_forever() on %s", self.listen_on)
        while True:
            self.handle_request()
