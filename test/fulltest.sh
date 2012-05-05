#!/bin/sh -xe

#./sslcaudit --no-default-cn --user-cn localhost --user-ca-cert test/certs/sslcaudit-test-cacert.pem --user-ca-key test/certs/sslcaudit-test-cakey.pem --server 62.213.200.252:443 --no-self-signed

#./sslcaudit -v 1 --user-cn localhost \
#	--user-cert test/certs/sslcaudit-test.gremwell.com-cert.pem --user-key test/certs/sslcaudit-test.gremwell.com-key.pem \
#	--user-ca-cert test/certs/sslcaudit-test-cacert.pem --user-ca-key test/certs/sslcaudit-test-cakey.pem

./sslcaudit --user-cn localhost \
	--server 62.213.200.252:443 \
	--user-cert test/certs/sslcaudit-test.gremwell.com-cert.pem --user-key test/certs/sslcaudit-test.gremwell.com-key.pem \
	--user-ca-cert test/certs/sslcaudit-test-cacert.pem --user-ca-key test/certs/sslcaudit-test-cakey.pem $*

