#!/bin/sh -xe

../dnsperf -h
../resperf -h

! ../dnsperf -O suppress
! ../dnsperf -O suppress=
! ../resperf -O suppress
! ../resperf -O suppress=
