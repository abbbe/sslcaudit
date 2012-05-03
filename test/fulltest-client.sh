#!/bin/sh -xe

#cmd="./openssl-1.0.1b/apps/openssl s_client -connect localhost:8443 -CAfile test/certs/sslcaudit-test-cacert.pem -showcerts -verify 9 -showcerts"
cmd="socat - OPENSSL:localhost:8443,cafile=test/certs/sslcaudit-test-cacert.pem"

while
	$cmd < /dev/null
do 
	echo '--------------------------------------------------------------------------------------'
	sleep .5
done
