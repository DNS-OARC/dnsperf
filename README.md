# dnsperf

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnsperf&metric=bugs)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnsperf) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3Adnsperf&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=dns-oarc%3Adnsperf)

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

See also the `dnsperf(1)` and `resperf(1)` man pages.

More information may be found here:
- https://www.dns-oarc.net/tools/dnsperf

Issues should be reported here:
- https://codeberg.org/DNS-OARC/dnsperf/issues

General support and discussion:
- Mattermost: https://chat.dns-oarc.net/community/channels/oarc-software

## Usage

`dnsperf` and `resperf` read input files describing DNS queries, and send
those queries to DNS servers to measure performance.

## Dependencies

`dnsperf` requires a couple of libraries beside a normal C compiling
environment with autoconf, automake, libtool and pkgconfig.

- [OpenSSL](https://www.openssl.org/) - for TSIG support
- [Concurrency Kit](http://concurrencykit.org/) - for atomic operations
- [LDNS](https://nlnetlabs.nl/projects/ldns/about/) - optional for dynamic update support
- [nghttp2](https://nghttp2.org) - for DNS-over-HTTPS support using HTTP/2

To install the dependencies under Debian/Ubuntu:
```
apt-get install -y libssl-dev libldns-dev libck-dev libnghttp2-dev
```

To install the dependencies under CentOS (with EPEL/PowerTools enabled):
```
yum install -y openssl-devel ldns-devel ck-devel libnghttp2-devel
```

To install the dependencies under FreeBSD 12+ using `pkg`:
```
pkg install -y openssl ldns concurrencykit libnghttp2
```

To install the dependencies under OpenBSD 6+ using `pkg_add`:
```
pkg_add libldns nghttp2
```

## Building from source tarball

The [source tarball from DNS-OARC](https://www.dns-oarc.net/tools/dnsperf)
comes prepared with `configure`:

```
tar zxvf dnsperf-version.tar.gz
cd dnsperf-version
./configure [options]
make
make install
```

## Building from Git repository

```
git clone https://codeberg.org/DNS-OARC/dnsperf.git
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
Copyright 2019-2024 OARC, Inc.
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
