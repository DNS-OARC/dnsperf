# Copyright 2019-2022 OARC, Inc.
# Copyright 2017-2018 Akamai Technologies
# Copyright 2006-2016 Nominum, Inc.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/config.h.in
CLEANFILES = dnsperf.1 resperf.1 *.gcda *.gcno *.gcov

SUBDIRS = test

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(PTHREAD_CFLAGS) $(libssl_CFLAGS) $(libcrypto_CFLAGS) $(libldns_CFLAGS)

EXTRA_DIST = dnsperf.1.in resperf-report resperf.1.in

bin_PROGRAMS = dnsperf resperf
dist_bin_SCRIPTS = resperf-report

_libperf_sources = datafile.c dns.c log.c net.c opt.c os.c strerror.c qtype.c \
  edns.c tsig.c net_udp.c net_tcp.c net_dot.c net_doh.c parse_uri.c
_libperf_headers = datafile.h dns.h log.h net.h opt.h os.h util.h strerror.h \
  list.h result.h buffer.h qtype.h edns.h tsig.h parse_uri.h

dnsperf_SOURCES = $(_libperf_sources) dnsperf.c hg64.c
dist_dnsperf_SOURCES = $(_libperf_headers) hg64.h
dnsperf_LDADD = $(PTHREAD_LIBS) $(libssl_LIBS) $(libcrypto_LIBS) \
  $(libldns_LIBS) $(libnghttp2_LIBS)

resperf_SOURCES = $(_libperf_sources) resperf.c
dist_resperf_SOURCES = $(_libperf_headers)
resperf_LDADD = $(PTHREAD_LIBS) $(libssl_LIBS) $(libcrypto_LIBS) \
  $(libldns_LIBS) $(libnghttp2_LIBS)

man1_MANS = dnsperf.1 resperf.1

dnsperf.1: dnsperf.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
-e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
-e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
< $(srcdir)/dnsperf.1.in > dnsperf.1

resperf.1: resperf.1.in Makefile
	sed -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
-e 's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g' \
-e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
< $(srcdir)/resperf.1.in > resperf.1

if ENABLE_GCOV
gcov-local:
	for src in $(_libperf_sources) dnsperf.c resperf.c; do \
	  gcov -l -r -s "$(srcdir)" "$$src"; \
	done
endif
