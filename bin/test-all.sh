#!/bin/sh -xe

bin/test-sslcaudit

for testno in 1 2 3; do
	bin/sslcaudit \
		--user-cn localhost \
		--server 62.213.200.252:443 \
		--user-cert test/certs/www.example.com-cert.pem --user-key test/certs/www.example.com-key.pem \
		--user-ca-cert test/certs/test-ca-cacert.pem --user-ca-key test/certs/test-ca-cakey.pem \
		-T $testno
done

bin/cleanup.sh

