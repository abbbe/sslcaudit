#!/bin/sh -x
../../bin/sslcaudit --server localhost:7443 --user-ca-cert=txjsonrpc/test/certs/txjsonrpc-test-ca-cacert.pem --user-ca-key=txjsonrpc/test/certs/cacert.key
