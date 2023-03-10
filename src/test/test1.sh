#!/bin/sh -xe

../dnsperf -h
../resperf -h

! ../dnsperf -O suppress
! ../dnsperf -O suppress=
! ../resperf -O suppress
! ../resperf -O suppress=

# test for broken long opt in v2.11.0
../dnsperf -O suppress=test 2>&1 |grep -q "unknown message type to suppress: test"
