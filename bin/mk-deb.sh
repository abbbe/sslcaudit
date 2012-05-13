#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

python setup.py --command-packages=stdeb.command bdist_deb

dpkg -I deb_dist/python-sslcaudit_1.0-1_all.deb
