#!/bin/sh -xe

./sslcaudit --user-cn localhost --user-ca-cert test/certs/sslcaudit-test-cacert.pem --user-ca-key test/certs/sslcaudit-test-cakey.pem --server 62.213.200.252:443 --no-self-signed

