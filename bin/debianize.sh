#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

rm -rf debian
python setup.py --command-packages=stdeb.command debianize

cp COPYING.TXT debian/copyright
patch debian/control <<'END'
10c10
< Depends: ${misc:Depends}, ${python:Depends}
---
> Depends: ${misc:Depends}, ${python:Depends}, python-m2crypto
END
