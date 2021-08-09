#!/bin/sh -xe

test "$TEST_DNSPERF_WITH_NETWORK" = "1" || exit 0

for ip in 1.1.1.1 2606:4700:4700::1111; do

echo "google.com A" | ../dnsperf -vvv -s $ip -m udp >test2.out
cat test2.out
grep -q "Queries sent: *1" test2.out
echo "google.com A" | ../dnsperf -vvv -s $ip -e -E 12345:0a0a0a0a -m udp >test2.out
cat test2.out
grep -q "Queries sent: *1" test2.out
../dnsperf -vvv -s $ip -d "$srcdir/datafile" -n 2 -m udp >test2.out
cat test2.out
grep -q "Queries sent: *4" test2.out
../dnsperf -s $ip -d "$srcdir/datafile" -n 1 -m tcp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s $ip -d "$srcdir/datafile" -n 1 -m dot >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s $ip -d "$srcdir/datafile" -n 1 -m dot >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../dnsperf -s $ip -d "$srcdir/datafile3" -n 1 -m dot >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../dnsperf -s $ip -d "$srcdir/datafile" -n 1 -e >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../dnsperf -s $ip -d "$srcdir/datafile" -n 1 -e -D >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-md5:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out
../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-sha1:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out
../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-sha224:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out
../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-sha256:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out
../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-sha384:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out
../dnsperf -d "$srcdir/updatefile" -u -s $ip -y hmac-sha512:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Updates sent: *1" test2.out

../resperf -s $ip -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M udp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
../resperf -s $ip -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M tcp >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

../resperf -s $ip -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M udp -D >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out
# Disabled until https://github.com/DNS-OARC/dnsperf/issues/92 is fixed
../resperf -s $ip -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M udp -y hmac-sha256:test:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= >test2.out
cat test2.out
grep -q "Queries sent: *2" test2.out

# Ignore failure until https://github.com/DNS-OARC/dnsperf/issues/88 is fixed
# May work on slower systems
../resperf -s $ip -m 1 -d "$srcdir/datafile2" -r 2 -c 2 -M dot || true

# TYPE test
../dnsperf -s $ip -d "$srcdir/datafile5" -n 1 -W >test2.out
cat test2.out
grep -q "Queries sent: *4" test2.out
grep -q "Warning: invalid qtype: TYPE99999999" test2.out

done # for ip

../dnsperf -s 127.66.66.66 -d "$srcdir/datafile" -vvvv -m tcp -n 1 &
sleep 2
pkill -KILL -u `id -u` dnsperf || true

../dnsperf -s 127.66.66.66 -d "$srcdir/datafile" -vvvv -m dot -n 1 &
sleep 2
pkill -KILL -u `id -u` dnsperf || true

! echo "google.com A" \
  | ../dnsperf -W -s 1.1.1.1 -y tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong:Ax42vsuHBjQOKlVHO8yU1zGuQ5hjeSz01LXiNze8pb8= \
  | grep "adding TSIG: invalid owner name"
echo ".google.com A" | ../dnsperf -W -s 1.1.1.1 \
  | grep "invalid domain name"
echo "google.com.. A" | ../dnsperf -W -s 1.1.1.1 \
  | grep "invalid domain name"
echo " A" | ../dnsperf -W -s 1.1.1.1 \
  | grep "invalid query input format"
echo "toooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolongname" \
  | ../dnsperf -W -s 1.1.1.1 -u \
  | grep "Unable to parse domain name"
echo "tooooooooooooooooooooooooooooo.oooooooooooooooooooooooo.ooooooooooooooooooooooooooooo.ooooooooooooooooooooooooooooooo.oooooooooooooooooooooooooooooooooooooo.oooooooooooooooooooooooooooo.ooooooooooooooooooooooooo.ooooooooooooooooooooooooooooooooo.oooooooooooooooooooooooooooo.oooooooooooooooooooooooooooooooo.ooooooooooooooooooo.longname" \
  | ../dnsperf -W -s 1.1.1.1 -u \
  | grep "Unable to parse domain name"
echo -e "test\ndelete toooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooolongname" \
  | ../dnsperf -W -s 1.1.1.1 -u \
  | grep "invalid update command, domain name too large"
