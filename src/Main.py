import logging
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Main')

if __name__ == "__main__":
    parser = OptionParser(usage="sslcaudit ", version="sslcaudit 0.1")
    parser.add_option("-p", dest="port", help="Listening port")
    parser.add_option("-s", dest="server", help="Server host:port")
    #parser.add_option("-d", dest="debug", help="Destination IP address")
    (options, args) = parser.parse_args()

    if options.port == None:
        parser.error('Listening port parameter (-p) required')

    if options.server != None:
        server_cert = grab_server_cert(options.server)
    else:
        server_cert = None
    auditor_set = SSLClientAuditorSet(server_cert)

    auditor_set = DummyClientAuditorSet()
    server = ClientAuditorServer(("localhost", 9999), auditor_set)
    server.start()

    while True:
        res = server.res_queue.get()
        logger.debug("got result %s", res)
