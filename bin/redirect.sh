#!/bin/sh

ebtables -t broute -F
iptables -t nat -F
echo "ebtables/broute and iptables/nat tables are flushed"

if [ $# -eq 0 ] ; then
	exit 0
elif [ $# -eq 3 ] ; then
	addr=$1
	port=$2
	dport=$3
else
	echo "Usage: $0 ADDR PORT DPORT" >&2
	exit 1
fi

ebtables -t broute -A BROUTING -p IPv4 \
	--ip-protocol 6 --ip-destination $addr --ip-destination-port $port \
	-j redirect --redirect-target ACCEPT

iptables -t nat -A PREROUTING -p tcp -d $addr --dport $port -j REDIRECT --to-ports $dport
echo "redirecting bridged traffic $addr:$port -> $dport"
