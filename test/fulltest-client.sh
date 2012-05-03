#!/bin/sh

#cmd="./openssl-1.0.1b/apps/openssl s_client -connect localhost:8443 -CAfile test/certs/sslcaudit-test-cacert.pem -showcerts -verify 9 -showcerts"
#cmd="socat - OPENSSL:localhost:8443,cafile=test/certs/sslcaudit-test-cacert.pem"
cmd="curl --cacert test/certs/sslcaudit-test-cacert.pem https://localhost:8443/"

while true ; do
	$cmd < /dev/null
	sleep .5
done
