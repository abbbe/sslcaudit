#!/bin/sh -x

env PYTHONPATH="`dirname \"$0\"`" python src/Main.py $*
