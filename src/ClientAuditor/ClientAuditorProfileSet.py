class ClientAuditorProfileSet(object):
    '''A class containing a set of client audit profiles.'''
    def __init__(self, profiles):
        self.profiles = profiles

    def __iter__(self):
        return self.profiles.__iter__()
