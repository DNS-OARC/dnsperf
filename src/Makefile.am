# Copyright 2019 OARC, Inc.
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
CLEANFILES = dnsperf.1 resperf.1

SUBDIRS =

AM_CFLAGS = -I$(srcdir) \
  -I$(top_srcdir) \
  $(PTHREAD_CFLAGS) $(libssl_CFLAGS)

EXTRA_DIST = dnsperf.1.in resperf-report resperf.1.in

bin_PROGRAMS = dnsperf resperf
dist_bin_SCRIPTS = resperf-report

_libperf_sources = datafile.c dns.c log.c net.c opt.c os.c
_libperf_headers = datafile.h dns.h log.h net.h opt.h os.h util.h

dnsperf_SOURCES = $(_libperf_sources) dnsperf.c
dist_dnsperf_SOURCES = $(_libperf_headers)
dnsperf_LDADD = $(PTHREAD_LIBS) $(libssl_LIBS)

resperf_SOURCES = $(_libperf_sources) resperf.c
dist_resperf_SOURCES = $(_libperf_headers)
resperf_LDADD = $(PTHREAD_LIBS) $(libssl_LIBS)

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
