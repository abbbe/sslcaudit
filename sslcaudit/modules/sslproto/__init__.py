# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------
import M2Crypto
import logging
import os
from sslcaudit.modules.sslproto.suites import SUITES

ALL_PROTOCOLS = ('sslv2', 'sslv3', 'tlsv1')
EXPORT_CIPHER = 'EXPORT'
DEFAULT_CIPHER_SUITES = ('HIGH', 'MEDIUM', 'LOW', EXPORT_CIPHER)

SSL_CODES = dict(((getattr(M2Crypto.m2, _), _.upper()) for _ in filter(lambda _: _.upper().startswith("SSL_") and isinstance(getattr(M2Crypto.m2, _), int), dir(M2Crypto.m2))))
IS_SSLv2_SUPPORTED = hasattr(M2Crypto.m2, "sslv2_method") and M2Crypto.m2.ssl_ctx_new(M2Crypto.m2.sslv2_method()) is not None

_ = os.path.dirname(os.path.abspath(__file__))
EPHEMERAL_RSA_KEY = M2Crypto.RSA.load_key(os.path.join(_, "../../files/rsa512.pem"))  # ctx.set_tmp_rsa(EPHEMERAL_RSA_KEY)
EPHEMERAL_DH_PARAMS = os.path.join(_, "../../files/dh512.pem")  # ctx.set_tmp_dh(EPHEMERAL_DH_PARAMS)

supported_protocols = None
error_reported = False

def get_supported_protocols(quiet=False):
    """
    Determines the list of SSL protocols supported by OS.
    In quiet mode it does not log an error in case of lack of SSLv2 support.
    In non-quiet mode (by default) it logs an error (once).
    """
    global error_reported, supported_protocols

    if not quiet and not IS_SSLv2_SUPPORTED and not error_reported:
        logging.getLogger('sslproto').fatal('Excluding SSLv2 from the list of tested protocol because OS does not support it')
        error_reported = True

    if supported_protocols is None:
        supported_protocols = ('sslv3', 'tlsv1')
        if IS_SSLv2_SUPPORTED:
            supported_protocols += ('sslv2',)

    return supported_protocols

def resolve_ssl_code(code):
    """
    Resolves SSL codes in a human readable form (e.g. 3 -> 'SSL_ERROR_WANT_WRITE')
    """
    return SSL_CODES.get(code, "UNKNOWN")

def set_ephemeral_params(ctx):
    """
    Sets ephemeral params for given context needed by SSL server instances (e.g. EXPORT ciphers)
    """
    ctx.set_tmp_rsa(EPHEMERAL_RSA_KEY)
    ctx.set_tmp_dh(EPHEMERAL_DH_PARAMS)


def get_ciphers(proto):
    """ Returns a list of individual ciphers supported by given protocol.
    """
    return SUITES[proto]
