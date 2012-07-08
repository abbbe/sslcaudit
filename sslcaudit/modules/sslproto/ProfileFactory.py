# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------
import logging
from sslcaudit.core.CertFactory import CertFactory
from sslcaudit.core.ConfigError import ConfigError
from sslcaudit.modules import sslproto

from sslcaudit.modules.base.BaseProfileFactory import BaseProfileFactory, BaseProfile, BaseProfileSpec
from sslcaudit.modules.sslproto.ServerHandler import ServerHandler
from sslcaudit.modules.sslproto import DEFAULT_CIPHER_SUITES
from sslcaudit.modules.sslproto.suites import SUITES

SSLPROTO_CN = 'sslproto'
sslproto_server_handler = ServerHandler()

class SSLServerProtoSpec(BaseProfileSpec):
    def __init__(self, proto, cipher):
        self.proto = proto
        self.cipher = cipher

    def __str__(self):
        return "sslproto(%s, %s)" % (self.proto, self.cipher)

class SSLServerProtoProfile(BaseProfile):
    def __init__(self, profile_spec, certnkey):
        self.profile_spec = profile_spec
        self.certnkey = certnkey

    def get_spec(self):
        return self.profile_spec

    def get_handler(self):
        return sslproto_server_handler

    def __str__(self):
        return "%s" % (self.profile_spec)


class ProfileFactory(BaseProfileFactory):
    logger = logging.getLogger('sslproto.ProfileFactory')

    def __init__(self, file_bag, options):
        BaseProfileFactory.__init__(self, file_bag, options)

        # produce a self-signed server certificate
        cert_factory = CertFactory(self.file_bag)
        certreq_n_keys = cert_factory.mk_certreq_n_keys(SSLPROTO_CN)
        certnkey = cert_factory.sign_cert_req(certreq_n_keys, None)

        self.init_protocols(options.protocols)

        for proto in self.protocols:
            if not options.iterate_suites:
                ciphers = DEFAULT_CIPHER_SUITES
            else:
                ciphers = SUITES[proto]
            for cipher in ciphers:
                profile = SSLServerProtoProfile(SSLServerProtoSpec(proto, cipher), certnkey)
                self.add_profile(profile)

    def init_protocols(self, user_specified_protocols_str):
        """
        This method builds a list of protocols to cover and places into .protocols attribute of the factory.
        It will be used during server profile generation and by unittests.
        """

        if user_specified_protocols_str is None:
            # by default we test all protocols supported by the OS.
            # it is responsibility of sslproto.get_supported_protocols() to alert the users about missing OS features if any
            self.protocols = sslproto.get_supported_protocols()
        else:
            supported_protos = sslproto.get_supported_protocols(quiet=True)
            user_specified_protocols = []

            # check if protocols requested by the users are supported by OS
            # create a list of unsupported protocols
            unsupported_protos = []
            for proto in user_specified_protocols_str.split(','):
                proto.strip()
                if proto in supported_protos:
                    user_specified_protocols.append(proto)
                else:
                    unsupported_protos.append(proto)

            # if any protocols are not supported, raise an exception
            if len(unsupported_protos) > 0:
                raise ConfigError('Following SSL protocols are not supported by OS libraries: %s'
                    % ','.join(unsupported_protos))

            self.protocols = user_specified_protocols

    def __str__(self):
        return 'sslproto.ProfileFactory(protocols="%s", %d profiles loaded)' % (
            ','.join(self.protocols),
            len(self.profiles))
