# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------
import M2Crypto

IS_SSLv2_SUPPORTED = hasattr(M2Crypto.m2, "sslv2_method") and M2Crypto.m2.ssl_ctx_new(M2Crypto.m2.sslv2_method()) is not None

PROTOCOLS = filter(None, ('sslv2' if IS_SSLv2_SUPPORTED else None, 'sslv3', 'tlsv1'))
EXPORT_CIPHER = 'EXPORT'
CIPHERS = ('HIGH', 'MEDIUM', 'LOW', EXPORT_CIPHER)
