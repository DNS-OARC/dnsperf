# dnsperf

## Overview

[https://github.com/nominum/dnsperf](https://github.com/nominum/dnsperf)

This is a collection of DNS server performance testing tools, including dnsperf
and resperf.  For more information, see the dnsperf(1) and resperf(1) man pages.

## Usage

dnsperf and resperf read input files describing DNS queries, and send those
queries to DNS servers to measure performance.

## Installation

To configure, compile, and install these programs, follow these steps.

1. Make sure that BIND 9 (9.4.0 or greater) is installed, including libraries
   and header files, and that the isc-config.sh program distributed with BIND
   is in your path.
   
   Note: many versions of bind do not correctly install the <isc/hmacsha.h>
   header file, so if the compilation fails, obtain this file from the BIND
   source distribution, and install it in the appropriate place.

2. Run "sh configure" to configure the software.  Most standard configure
   options are supported.

3. Run "make" to build dnsperf and resperf

4. Run "make install" to install dnsperf and resperf.

## Additional Software

The contrib directory contains additional software related to dnsperf and
resperf.
