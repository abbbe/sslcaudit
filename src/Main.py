import logging
from src.ClientAuditor.ClientAuditorServer import ClientAuditorServer
from src.ClientAuditor.Dummy.DummyClientAuditorSet import DummyClientAuditorSet

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Main')

if __name__ == "__main__":
    auditor_set = DummyClientAuditorSet()
    server = ClientAuditorServer(("localhost", 9999), auditor_set)
    server.run()
