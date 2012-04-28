#!/bin/sh -x

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

for f in test/Test*.py ; do
	env PYTHONPATH="`dirname \"$0\"`" python $f
done
