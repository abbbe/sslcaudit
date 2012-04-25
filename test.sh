#!/bin/sh -x

env PYTHONPATH="`dirname \"$0\"`" python test/TestMain.py -v
