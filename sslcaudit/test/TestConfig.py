# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

import os

TEST_MAIN_JOIN_TIMEOUT = 60

TEST_USER_CN = 'user-cn.example.com'

TEST_SERVER_HOST = '62.213.200.252'
TEST_SERVER_PORT = 443
TEST_SERVER = '%s:%d' % (TEST_SERVER_HOST, TEST_SERVER_PORT)
TEST_SERVER_CN = 'brufeprd1.hackingmachines.com'

TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_BASEPORT = 10000

## figure out path to test/certs directory
if os.path.exists(os.path.join('..', 'test', 'certs')): TEST_CERT_DIR = os.path.join('..', 'test', 'certs')
elif os.path.exists(os.path.join('test', 'certs')): TEST_CERT_DIR = os.path.join('test', 'certs')
elif os.path.exists('certs'): TEST_CERT_DIR = 'certs'
else: raise RuntimeError('cannot find test/certs or certs/ directory')
TEST_CERT_DIR += os.sep

TEST_USER_CERT_CN = 'www.example.com'
TEST_USER_CERT_FILE = TEST_CERT_DIR + 'www.example.com-cert.pem'
TEST_USER_KEY_FILE = TEST_CERT_DIR + 'www.example.com-key.pem'

TEST_USER_CA_CN = 'test-ca'
TEST_USER_CA_CERT_FILE = TEST_CERT_DIR + 'test-ca-cacert.pem'
TEST_USER_CA_KEY_FILE = TEST_CERT_DIR + 'test-ca-cakey.pem'

def get_next_listener_port():
    '''
    This method used to allocate ports the test server will listen on
    '''
    global TEST_LISTENER_BASEPORT
    TEST_LISTENER_BASEPORT = TEST_LISTENER_BASEPORT + 1
    return TEST_LISTENER_BASEPORT


