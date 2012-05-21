#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

# This script builds .deb package, installs it locally,
# lists files deployed by the package, and uninstalls the package.

# build .deb file
bin/mk-deb-do.sh

# install
pkg=`ls ../python-sslcaudit*.deb`
ndebs=`echo $pkg | wc -w`
if [ $ndebs -ne 1 ] ; then
	echo "There must be one and only one python-sslcaudit deb package in the parent directory, found: $pkg" >&2
	exit 1
fi
sudo dpkg -i $pkg

# list files
dpkg -L python-sslcaudit

# test run
(
	cd /tmp
	which sslcaudit
	sslcaudit -T 1 --user-cn localhost
) || true

# uninstall
sudo dpkg -r python-sslcaudit

# done
echo "Built and tested .deb file: $pkg"
