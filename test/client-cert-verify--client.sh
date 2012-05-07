#!/bin/sh -x

socat -v - OPENSSL:localhost:18443,cert=test/certs/test-client-cert.pem,key=test/certs/test-client-key.pem,cafile=test/certs/test-ca-cacert.pem
