''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import sys, logging
from PyQt4 import QtGui

logger = logging.getLogger('SSLCAuditGUI')

class SSLCAuditGUI(object):
    def __init__(self, options):
        '''
        Initialize UI. Dictionary 'options' comes from SSLCAuditUI.parse_options().
        '''
        self.options = options

        # initialize dummy GUI
        self.app = QtGui.QApplication(sys.argv)
        self.w = QtGui.QWidget()
        self.w.resize(250, 150)
        self.w.move(300, 300)
        self.w.setWindowTitle('Simple')
        self.w.show()

    def run(self):
        return self.app.exec_()
