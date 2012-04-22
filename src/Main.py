import logging
from src.ClientAuditor import TCPClientAuditor
from src.ClientAuditor.Dummy.DummyProfileSet import DummyProfileSet

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Main')

if __name__ == "__main__":
    profile_set = DummyProfileSet()
    server = TCPClientAuditor.Server(("localhost", 9999), profile_set)
    server.serve_forever()
