# Copyright 2019-2024 OARC, Inc.
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

AC_PREREQ(2.64)
AC_INIT([dnsperf], [2.14.0], [admin@dns-oarc.net], [dnsperf], [https://codeberg.org/DNS-OARC/dnsperf/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/dnsperf.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

# for pthread_setname_np
# needs to be called before any macros that run the C compiler
AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
AC_C_INLINE
LT_INIT([disable-static])

# Check --enable-warn-all
AC_ARG_ENABLE([warn-all], [AS_HELP_STRING([--enable-warn-all], [Enable all compiler warnings])], [AX_CFLAGS_WARN_ALL()])

# Check --with-extra-cflags
AC_ARG_WITH([extra-cflags], [AS_HELP_STRING([--with-extra-cflags=CFLAGS], [Add extra CFLAGS])], [
  AC_MSG_NOTICE([appending extra CFLAGS... $withval])
  AS_VAR_APPEND(CFLAGS, [" $withval"])
])

# Check --with-extra-ldflags
AC_ARG_WITH([extra-ldflags], [AS_HELP_STRING([--with-extra-ldflags=LDFLAGS], [Add extra LDFLAGS])], [
  AC_MSG_NOTICE([appending extra LDFLAGS... $withval])
  AS_VAR_APPEND(LDFLAGS, [" $withval"])
])

# Check --enable-gcov
AC_ARG_ENABLE([gcov], [AS_HELP_STRING([--enable-gcov], [Enable coverage testing])], [
  coverage_cflags="--coverage -g -O0 -fno-inline -fno-inline-small-functions -fno-default-inline"
  AC_MSG_NOTICE([enabling coverage testing... $coverage_cflags])
  AS_VAR_APPEND(CFLAGS, [" $coverage_cflags"])
])
AM_CONDITIONAL([ENABLE_GCOV], [test "x$enable_gcov" != "xno"])
AM_EXTRA_RECURSIVE_TARGETS([gcov])

# Checks for support.
AX_PTHREAD
AC_CHECK_FUNCS([pthread_setname_np pthread_set_name_np])
AC_CHECK_HEADERS([pthread_np.h], [], [], [#include <pthread.h>])
AC_CHECK_LIB([m], [sqrt])
AC_CHECK_HEADERS([stdatomic.h])
AM_CONDITIONAL([HAVE_STDATOMIC], [test "x$ac_cv_header_stdatomic_h" != "xno"])

# Check for OpenSSL
PKG_CHECK_MODULES([libssl], [libssl])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
AC_CHECK_LIB([ssl], [TLS_method],
  [AC_DEFINE([HAVE_TLS_METHOD], [1], [Define to 1 if you have the 'TLS_method' function])])
PKG_CHECK_MODULES([ck], [ck >= 0], [
  AS_VAR_APPEND([CFLAGS], [" $ck_CFLAGS"])
  AS_VAR_APPEND([LIBS], [" $ck_LIBS"])
], [
  AC_CHECK_HEADERS([ck_ring.h ck_pr.h],, [AC_MSG_ERROR([libck headers not found])])
  AC_CHECK_LIB([ck], [ck_array_init],, [AC_MSG_ERROR([libck not found])])
])

# Check for LDNS
PKG_CHECK_MODULES([libldns], [libldns >= 1.7.0], [AC_DEFINE([HAVE_LDNS], [1], [Define to 1 if you have the LDNS library])], [
  PKG_CHECK_MODULES([libldns], [ldns >= 1.7.0], [AC_DEFINE([HAVE_LDNS], [1], [Define to 1 if you have the LDNS library])], [
    AC_MSG_NOTICE([LDNS (>= 1.7.0) not found, dynamic update support disabled])
  ])
])

# Check for nghttp2
PKG_CHECK_MODULES([libnghttp2], [libnghttp2 >= 0], [
  AS_VAR_APPEND([CFLAGS], [" $nghttp2_CFLAGS"])
  AS_VAR_APPEND([LIBS], [" $nghttp2_LIBS"])
], [
  AC_CHECK_HEADERS([nghttp2.h],, [AC_MSG_ERROR([nghttp2 headers not found])])
  AC_CHECK_LIB([nghttp2], [nghttp2_session],, [AC_MSG_ERROR([nghttp2 not found])])
])

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/test/Makefile
])
AC_OUTPUT
