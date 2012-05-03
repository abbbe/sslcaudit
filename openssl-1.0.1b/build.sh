#!/bin/sh -xe

./config -DOPENSSL_NO_CHAIN_VERIFY no-shared
make -j 16
make test

