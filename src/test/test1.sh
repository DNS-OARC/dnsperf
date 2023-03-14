#!/bin/sh -xe

../dnsperf -h
../resperf -h

! ../dnsperf -O suppress
! ../dnsperf -O suppress=
! ../resperf -O suppress
! ../resperf -O suppress=

# test for broken long opt in v2.11.0
../dnsperf -O suppress=test 2>&1 |grep -q "unknown message type to suppress: test"
# ...and in v2.11.1, issue #234
../dnsperf -O doh-uri=https://blahblah.com/dns-query -O suppress=timeouts -h