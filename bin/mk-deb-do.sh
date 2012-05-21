#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

# copy the licence file
cp COPYING.TXT debian/copyright

# build .deb file
dpkg-buildpackage -A -rfakeroot -uc -us -tc

