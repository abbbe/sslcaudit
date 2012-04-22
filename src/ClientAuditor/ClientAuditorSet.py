class ClientAuditorSet(object):
    '''
    This is a base class for sets of client auditors.
    '''

    def __init__(self, profiles):
        self.profiles = profiles

    def __iter__(self):
        return self.profiles.__iter__()
