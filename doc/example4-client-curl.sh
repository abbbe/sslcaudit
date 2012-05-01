#!/bin/sh -x
for _ in `seq 1 4` ; do curl --cacert /home/abb/certs/sslcaudit-test-cacert.pem https://brufeprd1.hackingmachines.com:8443/ ; done
