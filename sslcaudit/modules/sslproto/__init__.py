# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

PROTOCOLS = ('sslv2', 'sslv3', 'tlsv1')
EXPORT_CIPHER = 'EXPORT'
CIPHERS = ('HIGH', 'MEDIUM', 'LOW', EXPORT_CIPHER)
