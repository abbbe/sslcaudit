#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

# drop debian/
rm -rf debian

# rebuild debian/
python setup.py --command-packages=stdeb.command debianize

# copy the licence file
cp COPYING.TXT debian/copyright

# fix dependency (why 'debianize' does not do it?)
patch debian/control <<'END'
10c10
< Depends: ${misc:Depends}, ${python:Depends}
---
> Depends: ${misc:Depends}, ${python:Depends}, python-m2crypto
END

# fix source code format
echo 1.0 > debian/source/format

