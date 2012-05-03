''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

class BaseProfileFactory(object):
    '''
    This class contains a list of profiles (subclasses of BaseServerHandler class). Each module is
    expected to contain a subclass of this class named ProfileFactory. One instance of that subclass will be created
    when module gets loaded during program startup. Its constructor will receive a dictionary of command-line options
    and is expected to populate the list of profiles by invoking add_profile() method. The objects added into
    this list should extend BaseServerHandler class.
    '''

    def __init__(self, file_bag, options):
        self.file_bag = file_bag
        self.options = options
        self.profiles = []

    def add_profile(self, profile):
        self.profiles.append(profile)

    def __iter__(self):
        return self.profiles.__iter__()