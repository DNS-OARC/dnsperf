# dnsperf

[https://github.com/DNS-OARC/dnsperf](https://github.com/DNS-OARC/dnsperf)

`dnsperf` and `resperf` are free tools developed by Nominum/Akamai (2006-2018)
and DNS-OARC (since 2019) that make it simple to gather accurate latency and
throughput metrics for Domain Name Service (DNS). These tools are easy-to-use
and simulate typical Internet, so network operators can benchmark their naming
and addressing infrastructure and plan for upgrades. The latest version of
the `dnsperf` and `resperf` can be used with test files that include IPv6
queries.

`dnsperf` "self-paces" the DNS query load to simulate network conditions.
New features in `dnsperf` improve the precision of latency measurements and
allow for per packet per-query latency reporting is possible. `dnsperf` is
now multithreaded, multiple `dnsperf` clients can be supported in multicore
systems (each client requires two cores). The output of `dnsperf` has also
been improved so it is more concise and useful. Latency data can be used to
make detailed graphs, so it is simple for network operators to take advantage
of the data.

`resperf` systematically increases the query rate and monitors the response
rate to simulate caching DNS services.

For more information, see the `dnsperf(1)` and `resperf(1)` man pages.

## Usage

`dnsperf` and `resperf` read input files describing DNS queries, and send
those queries to DNS servers to measure performance.

## Dependencies

`dnsperf` requires a couple of libraries beside a normal C compiling
environment with autoconf, automake, libtool and pkgconfig.

`dnsperf` has a non-optional dependency on the BIND library and development
files along with all dependencies it requires.

To install the dependencies under Debian/Ubuntu:
```
apt-get install -y libbind-dev libkrb5-dev libssl-dev libcap-dev libxml2-dev libjson-c-dev libgeoip-dev
```

Depending on how BIND is compiled on Debian and Ubuntu you might need these
dependencies also:
```
apt-get install -y libprotobuf-c-dev libfstrm-dev liblmdb-dev libssl-dev
```

To install the dependencies under CentOS (with EPEL enabled):
```
yum install -y bind-devel krb5-devel openssl-devel libcap-devel libxml2-devel json-c-devel GeoIP-devel
```

To install the dependencies under FreeBSD 12+ using `pkg`:
```
pkg install -y bind913-9.13.5 openssl-devel GeoIP
```

To install the dependencies under OpenBSD 6+ using `pkg_add`:
```
pkg_add isc-bind-9.11.4pl2 GeoIP
```

## Building from source tarball

The source tarball from DNS-OARC comes prepared with `configure`:

```
tar zxvf dnsperf-version.tar.gz
cd dnsperf-version
./configure [options]
make
make install
```

## Building from Git repository

```
git clone https://github.com/DNS-OARC/dnsperf.git
cd dnsperf
./autogen.sh
./configure [options]
make
make install
```

## Additional Software

The contrib directory contains additional software related to `dnsperf` and
`resperf`.

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
