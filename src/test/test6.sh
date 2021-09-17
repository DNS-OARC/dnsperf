#!/bin/sh -xe

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

../dnsperf -vvv -d "$srcdir/datafile6" -s 1.1.1.1 >test6.out

grep "NXDOMAIN 26" test6.out
