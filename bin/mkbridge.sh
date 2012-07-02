#!/bin/sh -xe

BRIDGE=br0

brctl addbr $BRIDGE

for iface in $* ; do
	ifdown $iface || true
	ifconfig $iface 0 up

	brctl addif $BRIDGE $iface
done

ifconfig br0 up
