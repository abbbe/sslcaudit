#!/bin/sh -x

ciphers="HIGH MEDIUM LOW EXPORT56 EXPORT40 NULL"
methods="SSLv2 SSLv3 TLSv1"
verify="0 1"

seed=`date`

do_test() {
	method=$method ; shift;
	cipher_str=$cipher_str ; shift
	verify=$verify ; shift

	# prepare a token
	token=`echo $seed | sha1sum | awk '{print $1}'`
	seed=$token
	
	# start sslcaudit
	sslcaudit_outf=`mktemp`
	sslcaudit -h $host -p $port -o "$sslcaudit_outf"
	socat OPENSSL:$host:$port,cipher=$cipher > $client_outf &

	# start a client
	socat EXEC:'echo OK' OPENSSL:$host:$port,cipher=$cipher > $client_outf &
	sleep 1
}

for method in $methods ; do
	for cipher_str in $ciphers ; do
		for verify in 0 1 ; do
			do_test $method $cipher_str $verify
		done
	done
done

