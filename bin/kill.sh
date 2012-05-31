#!/bin/sh -e

# ----------------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------------

pid=`ps ax|grep sslcaudit| grep -v grep | awk '{print $1}'`
if [ -n "$pid" ] ; then
	kill -9 $pid
	echo "killed $pid"
else
	echo "nothinig to kill"
fi

