# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------
import M2Crypto
import logging

ALL_PROTOCOLS = ('sslv2', 'sslv3', 'tlsv1')
EXPORT_CIPHER = 'EXPORT'
ALL_CIPHERS = ('HIGH', 'MEDIUM', 'LOW', EXPORT_CIPHER)

supported_protocols = None

def get_supported_protocols(raw=False):
    """
    Determines the list of SSL protocols supported by OS.
    In raw mode it does not cache the results and does not log an error in case of lack of SSLv2 support.
    In non-raw mode (by default) the results get cached and an error is logged (once).
    """
    if not raw:
        global supported_protocols
        if supported_protocols is not None:
            return supported_protocols

    IS_SSLv2_SUPPORTED = hasattr(M2Crypto.m2, "sslv2_method") and M2Crypto.m2.ssl_ctx_new(M2Crypto.m2.sslv2_method()) is not None

    supported_protocols = ('sslv3', 'tlsv1')
    if IS_SSLv2_SUPPORTED:
        supported_protocols += ('sslv2',)
    else:
        if not raw:
            logging.getLogger('sslproto').fatal('Excluding SSLv2 from the list of tested protocol because OS does not support it')

    return supported_protocols