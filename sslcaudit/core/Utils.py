# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import re
import socket

def parse_hostport(hostport):
    '''
    This function receives HOST:PORT string specification (PORT is integer or a service name)
    and converts it to (HOST, INTPORT) tuple, where INTPORT is a numeric value. Almost no
    validation is done for the host name.
    '''
    match = re.match('^([\w\.\:\-]+):([\w\-]+)$', hostport)

    if match is None:
        raise ValueError('invalid HOST:PORT specification (bad format): %s' % hostport)

    try:
        # convert port to integer
        port = int(match.group(2))
        return (match.group(1), port)
    except ValueError:
        pass

    try:
        # try to lookup the port by TCP service name
        port = socket.getservbyname(match.group(2), 'tcp')
        return (match.group(1), port)
    except socket.error:
        raise ValueError('invalid HOST:PORT specification (unknown service): %s' % hostport)

