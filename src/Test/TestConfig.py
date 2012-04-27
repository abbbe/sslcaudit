''' ----------------------------------------------------------------------
SSLCAUDIT - a tool for automatingsecurity audit of SSL clients
Released under terms of GPLv3, see COPYING.TXT
Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
---------------------------------------------------------------------- '''
TEST_LISTENER_ADDR = 'localhost'
TEST_LISTENER_BASEPORT = 10000

MAIN_JOIN_TIMEOUT = 5

SSL_CLIENT_EXPECTED_CN = 'trusted.gremwell.com'

def get_next_listener_port():
    '''
    This method used to allocate ports the test server will listen on
    '''
    global TEST_LISTENER_BASEPORT
    TEST_LISTENER_BASEPORT = TEST_LISTENER_BASEPORT + 1
    return TEST_LISTENER_BASEPORT


