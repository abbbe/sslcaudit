#!/bin/sh -x

socat -v OPENSSL-LISTEN:18443,reuseaddr,fork,cert=test/certs/www.example.com-cert.pem,key=test/certs/www.example.com-key.pem,cafile=test/certs/test-ca-cacert.pem,verify=1 -
