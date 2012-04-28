''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automating security audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''

TEST_MAIN_JOIN_TIMEOUT = 5

TEST_USER_CN = 'nonexistent2.gremwell.com'

TEST_SERVER_HOST = 'gmail.google.com'
TEST_SERVER_PORT = 443
TEST_SERVER = '%s:%d' % (TEST_SERVER_HOST, TEST_SERVER_PORT)
TEST_SERVER_CN = '*.google.com'

TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_BASEPORT = 10000

def get_next_listener_port():
    '''
    This method used to allocate ports the test server will listen on
    '''
    global TEST_LISTENER_BASEPORT
    TEST_LISTENER_BASEPORT = TEST_LISTENER_BASEPORT + 1
    return TEST_LISTENER_BASEPORT


