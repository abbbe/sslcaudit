''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

from src.modules.base.BaseProfileFactory import BaseProfileFactory
from src.modules.dummy.DummyServerHandler import DummyServerHandler

class ProfileFactory(BaseProfileFactory):
    '''
    This is a dummy auditor set, containing only two dummy auditors.
    '''
    def __init__(self, file_bag, options):
        BaseProfileFactory.__init__(self, file_bag, options)

        self.add_profile(DummyServerHandler(False))
        self.add_profile(DummyServerHandler(True))
