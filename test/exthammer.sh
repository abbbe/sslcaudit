#!/bin/sh -xe

# ----------------------------------------------------------------------
# SSLCAUDIT - a tool for automating security audit of SSL clients
# Released under terms of GPLv3, see COPYING.TXT
# Copyright (C) 2012 Alexandre Bezroutchko abb@gremwell.com
# ----------------------------------------------------------------------

#
# Tries to run
# Exits with 0 if all went through, 1 if hammer fails
#

ciphers='HIGH MEDIUM LOW EXPORT56 EXPORT40 NULL'
methods='SSLv2 SSLv3 TLSv1'
verify='0 1'

sslcaudit=./sslcaudit
test_host='localhost'
test_port='8443'

wait_on_prefail=.25
max_nprefailures=12
wait_on_postfail=.25
max_npostfailures=2

outf=`mktemp`

do_test() {
	local method=$1
	local cipher=$2
	local verify=$3

	# start sslcaudit in background
	$sslcaudit -N "$mode $cipher $verify" -l $test_host -p $test_port &
	sslcaudit_pid=$!

	# start hammering
	hammer_outf="$outf.hout"

	nprefailures=0
	nconnected=0
	npostfailures=0
	while true ; do
		if ${0}_$mode $test_host $test_port $cipher $verify >> $hammer_outf 2>&1 ; then
			if [ $npostfailures -gt 0 ] ; then
				# connect after a postfailure? wierd
				echo "ERROR: connect after npostfailures=$npostfailures"
				cat $hammer_outf
				exit 1 
			else
				# connected
				nconnected=`expr $nconnected + 1`
			fi
		else
			if [ $nconnected -eq 0 ] ; then
				# prefailure
				nprefailures=`expr $nprefailures + 1`
				if [ $nprefailures -ge $max_nprefailures ] ; then
					echo "ERROR: nprefailures=$nprefailures > 3"
					cat $hammer_outf
					exit 1
				fi

				sleep $wait_on_prefail
			else
				# postfailure
				npostfailures=`expr $npostfailures + 1`
				[ $npostfailures -ge $max_npostfailures ] && break

				sleep $wait_on_postfail
			fi
		fi
	done

	# let sslcaudit die
	wait $sslcaudit_pid
}

do_tests() {
	local method
	for method in $methods ; do
		local cipher
		for cipher_str in $ciphers ; do
			local verify
			for verify in 0 1 ; do
				do_test $method $cipher_str $verify
			done
		done
	done
}

# -----------------------------------------------------------------

[ $# -eq 1 ] || exit

local mode=$1

do_tests $mode

exit 0
