# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

from sslcaudit.modules.base.BaseProfileFactory import BaseProfileFactory
from sslcaudit.core.ClientConnectionAuditEvent import ClientConnectionAuditResult
from sslcaudit.modules.base.BaseServerHandler import BaseServerHandler

class DummyServerProfile(object):
    '''
    This dummy profile contains one value only
    '''

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return 'dummy(%s)' % (self.value)

    def get_handler(self):
        return dummy_server_handler


class DummyServerHandler(BaseServerHandler):
    '''
    This dummy server handler does nothing, but returns a value from the profile.
    '''

    def handle(self, conn, profile):
        # do nothing with client connection
        # just return a value from the profile as a result
        return ClientConnectionAuditResult(conn, profile, profile.value)


class ProfileFactory(BaseProfileFactory):
    '''
    This profile factory contains two dummy profiles and a dummy handler.
    '''

    def __init__(self, file_bag, options):
        BaseProfileFactory.__init__(self, file_bag, options)

        self.add_profile(DummyServerProfile(False))
        self.add_profile(DummyServerProfile(True))

dummy_server_handler = DummyServerHandler()
