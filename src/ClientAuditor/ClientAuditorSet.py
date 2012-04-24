class ClientAuditorSet(object):
    '''
    This is a base class for sets of client auditors.
    '''

    def __init__(self, auditors):
        self.auditors = auditors

    def __iter__(self):
        return self.auditors.__iter__()
