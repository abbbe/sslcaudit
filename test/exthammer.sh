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

ciphers='HIGH MEDIUM LOW EXPORT40 NULL'
methods='SSLv2 SSLv3 TLSv1'

sslcaudit="./sslcaudit --user-cn=user-cn.nonexistent.gremwell.com"
test_host='localhost'
test_port='8443'

wait_on_prefail=.1
max_nprefailures=10
max_nconnected=10
wait_on_postfail=.1
max_npostfailures=2

NAMEWIDTH=-25

do_test() {
	local hammer=$1
	local method=$2
	local cipher=$3

	outf=`mktemp`

	test_name="$hammer $method $cipher"

	# start sslcaudit in background
	sslcaudit_errf="$outf.sslcaudit"

	$sslcaudit -N "$test_name" -l $test_host:$test_port 2> "$sslcaudit_errf" &
	sslcaudit_pid=$!

	# start hammering
	hammer_outf="$outf.hout"

	nprefailures=0
	nconnected=0
	npostfailures=0

	echo "START" >> $hammer_outf
	while true ; do
		if ${0}_$hammer $test_host $test_port $method $cipher >> $hammer_outf 2>&1 ; then
			echo "# CONNECTED" >> $hammer_outf
			if [ $npostfailures -gt 0 ] ; then
				# connect after a postfailure? wierd
				echo "ERROR: connect after npostfailures=$npostfailures"
				#cat $hammer_outf
				kill $sslcaudit_pid || true
				break
			else
				nconnected=`expr $nconnected + 1`
				if [ $nconnected -ge $max_nconnected ] ; then
					printf "%${NAMEWIDTH}s %s\n" "$test_name" "*** excessive nconnected=$nconnected ***"
					kill $sslcaudit_pid || true
					break
				fi
			fi
		else
			if [ $nconnected -eq 0 ] ; then
				echo "# PREFAILURE" >> $hammer_outf
				nprefailures=`expr $nprefailures + 1`
				if [ $nprefailures -ge $max_nprefailures ] ; then
					printf "%${NAMEWIDTH}s %s\n" "$test_name" "*** excessive nprefailures=$nprefailures ***"
					kill $sslcaudit_pid || true
					break
				fi

				sleep $wait_on_prefail
			else
				echo "# POSTFAILURE" >> $hammer_outf
				npostfailures=`expr $npostfailures + 1`
				[ $npostfailures -ge $max_npostfailures ] && break

				sleep $wait_on_postfail
			fi
		fi
	done

	# let sslcaudit die, don't care if it is unwell
	wait $sslcaudit_pid || true
}

do_tests() {
	local hammer=$1
	local method
	for method in $methods ; do
		local cipher
		for cipher_str in $ciphers ; do
			do_test $hammer $method $cipher_str
		done
	done
}

# -----------------------------------------------------------------

#[ $# -eq 1 ] || exit
#local hammer=$1

do_tests socat

exit 0
