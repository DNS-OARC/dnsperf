#!/bin/sh -xe

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

../dnsperf -vvv -s 1.1.1.1 -d "$srcdir/datafile" -n 1 -m udp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s 1.1.1.1 -d "$srcdir/datafile" -n 1 -m tcp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s 1.1.1.1 -d "$srcdir/datafile" -n 1 -m tls >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../dnsperf -s 1.1.1.1 -d "$srcdir/datafile" -n 1 -e >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s 1.1.1.1 -d "$srcdir/datafile" -n 1 -e -D >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../dnsperf -d "$srcdir/updatefile" -u -s 1.1.1.1 -y hmac-sha256:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out

../resperf -s 1.1.1.1 -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M udp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../resperf -s 1.1.1.1 -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M tcp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
# Ignore failure until https://github.com/DNS-OARC/dnsperf/issues/88 is fixed
# May work on slower systems
../resperf -s 1.1.1.1 -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M tls || true

../dnsperf -s 127.66.66.66 -d "$srcdir/datafile" -vvvv -m tcp -n 1 &
sleep 2
pkill -KILL -u `id -u` dnsperf || true

../dnsperf -s 127.66.66.66 -d "$srcdir/datafile" -vvvv -m tls -n 1 &
sleep 2
pkill -KILL -u `id -u` dnsperf || true
