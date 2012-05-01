#!/bin/sh -x
for _ in `seq 1 4` ; do socat - OPENSSL:localhost:8443,cafile=/home/abb/certs/sslcaudit-test-cacert.pem ; done
