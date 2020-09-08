#!/bin/sh -xe

! ../dnsperf -d does_not_exist
! ../resperf -d does_not_exist
! ../dnsperf -f invalid
! ../dnsperf -f any -s 256.256.256.256
! ../dnsperf -f inet -s 256.256.256.256
! ../dnsperf -f inet6 -s 256.256.256.256
! ../dnsperf -a 127.0.0.1 -d does_not_exist
! ../dnsperf -a ::1 -d does_not_exist
! ../dnsperf -a 256.256.256.256
! ../dnsperf -m invalid
! ../dnsperf -n 43f8huishfs
! ../dnsperf -p 12345 unexpected argument

! ../resperf -d does_not_exist
! ../resperf -r 0 -c 0
! ../resperf -f invalid
! ../resperf -q 256000
! ../resperf -m 123.45 unexpected argument
! ../resperf -m 123..
! ../resperf -m 123a
