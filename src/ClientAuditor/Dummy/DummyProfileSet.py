from src.ClientAuditor.ClientAuditorProfileSet import ClientAuditorProfileSet
from src.ClientAuditor.Dummy.DummyProfile import DummyProfile

class DummyProfileSet(ClientAuditorProfileSet):
    def __init__(self):
        ClientAuditorProfileSet.__init__(self, [DummyProfile()])
