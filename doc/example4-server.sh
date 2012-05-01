#!/bin/sh -x
./sslcaudit --user-ca-cert \
	~/certs/sslcaudit-test-cacert.pem \
	--user-ca-key ~/certs/sslcaudit-test-cakey.pem \
	--server 62.213.200.252:443
