# dnsperf

## Overview

[https://github.com/DNS-OARC/dnsperf](https://github.com/DNS-OARC/dnsperf)

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

   On Ubuntu / Debian:
   ```
   sudo apt-get install -y bind9utils libbind-dev libkrb5-dev libssl-dev libcap-dev libxml2-dev libjson-c-dev libgeoip-dev
   ```

2. Run "sh configure" to configure the software.  Most standard configure
   options are supported.

3. Run "make" to build dnsperf and resperf

4. Run "make install" to install dnsperf and resperf.

## Additional Software

The contrib directory contains additional software related to dnsperf and
resperf.

## License

```
Copyright 2019 OARC, Inc.
Copyright 2017-2018 Akamai Technologies
Copyright 2006-2016 Nominum, Inc.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
