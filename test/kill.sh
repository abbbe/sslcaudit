#!/bin/sh -e

pid=`ps ax|grep sslcaudit| grep -v grep | awk '{print $1}'`
if [ -n "$pid" ] ; then
	kill $pid
	echo "killed $pid"
else
	echo "nothinig to kill"
fi

