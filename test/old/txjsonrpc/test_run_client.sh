#!/bin/sh -x
while sleep .1 ; do PYTHONPATH=. python examples/ssl/client.py 8443 ; done
