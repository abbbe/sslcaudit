from src.ClientAuditor.ClientAuditorProfile import ClientAuditResult, ClientAuditorProfile

class DummyResult(ClientAuditResult):
    pass

class DummyProfile(ClientAuditorProfile):
    def handle(self, request):
        return DummyResult()
