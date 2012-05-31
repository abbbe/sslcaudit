# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

class BaseProfileSpec(object):
    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.__dict__ == other.__dict__

class BaseProfile(object):
    '''
    Base object for all profiles.
    Can return its specification.
    Can return a suitable handler.
    '''

    def get_spec(self):
        raise NotImplemented('subclasses must override this method')

    def get_handler(self):
        raise NotImplemented('subclasses must override this method')


class BaseProfileFactory(object):
    '''
    This class contains a list of profiles (subclasses of BaseProfile class). Each module is
    expected to contain a subclass of this class named ProfileFactory. Single instance of that subclass will be created
    when module gets loaded during program startup. Its constructor will receive a dictionary of command-line options
    and is expected to populate the list of profiles by invoking add_profile() method. The objects added into
    this list should extend BaseProfile class.
    '''

    def __init__(self, file_bag, options):
        self.file_bag = file_bag
        self.options = options
        self.profiles_ = []

    def add_profile(self, profile):
        self.profiles_.append(profile)

    def __iter__(self):
        return self.profiles_.__iter__()
