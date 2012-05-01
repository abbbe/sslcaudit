''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

import os

TEST_MAIN_JOIN_TIMEOUT = 60

TEST_USER_CN = 'user-cn.nonexistent.gremwell.com'

TEST_SERVER_HOST = '62.213.200.252'
TEST_SERVER_PORT = 443
TEST_SERVER = '%s:%d' % (TEST_SERVER_HOST, TEST_SERVER_PORT)
TEST_SERVER_CN = 'brufeprd1.hackingmachines.com'

TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_BASEPORT = 10000

#def get_testfile_path(filename):
#    ''' This function finds proper path to a file under test/ directory. Needed to ensure unittests work regardless of workdir '''
#
#    if os.path.isfile(filename): return filename
#    else:
#        filename2 = 'test/' + filename
#        if os.path.isfile(filename2): return filename2
#        else: raise RuntimeError("Can't find location of test file %s", filename)

TEST_CERT_DIR = os.getenv('HOME') + '/certs/'
TEST_USER_CERT_CN = 'sslcaudit-test.gremwell.com'
TEST_USER_CERT_FILE = TEST_CERT_DIR + 'sslcaudit-test.gremwell.com-cert.pem'
TEST_USER_KEY_FILE = TEST_CERT_DIR + 'sslcaudit-test.gremwell.com-key.pem'

TEST_USER_CA_CN = 'sslcaudit-test'
TEST_USER_CA_CERT_FILE = TEST_CERT_DIR + 'sslcaudit-test-cacert.pem'
TEST_USER_CA_KEY_FILE = TEST_CERT_DIR + 'sslcaudit-test-cakey.pem'

def get_next_listener_port():
    '''
    This method used to allocate ports the test server will listen on
    '''
    global TEST_LISTENER_BASEPORT
    TEST_LISTENER_BASEPORT = TEST_LISTENER_BASEPORT + 1
    return TEST_LISTENER_BASEPORT


