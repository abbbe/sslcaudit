#!/bin/sh -x

for m in TestMainDummy TestMainSSL ; do
	env PYTHONPATH="`dirname \"$0\"`" python test/$m.py -v
done
