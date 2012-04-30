#!/bin/sh -xe

#ps ax|grep sslcaudit| grep -v grep | awk '{print $1}' | xargs kill
ps ax|grep sslcaudit| grep -v grep | awk '{print $1}' 
