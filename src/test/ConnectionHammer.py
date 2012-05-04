from src.test.Hammer import Hammer

__author__ = 'abb'

class ConnectionHammer(Hammer):
    def __init__(self, peer):
        Hammer.__init__(self, nattempts)
        self.peer = peer
        self.delay_before_close = 60