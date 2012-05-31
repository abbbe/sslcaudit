# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

class ConfigError(Exception):
    '''
    The code has to throw this exception if it has a problem with input
    parameters. Should only be thrown during startup.
    '''
