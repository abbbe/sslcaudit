#!/bin/sh -xe

# execute unit-tests
for testno in 1 2 3; do
	bin/sslcaudit \
		--user-cn localhost \
		--server 62.213.200.252:443 \
		--user-cert test/certs/www.example.com-cert.pem --user-key test/certs/www.example.com-key.pem \
		--user-ca-cert test/certs/test-ca-cacert.pem --user-ca-key test/certs/test-ca-cakey.pem \
		-T $testno
done

# execute self-tests
bin/test-sslcaudit

# build and test debian package
bin/mk-deb.sh

# cleanup
bin/clean.sh

