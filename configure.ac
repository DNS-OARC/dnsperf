# Copyright 2019-2020 OARC, Inc.
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
AC_INIT([dnsperf], [2.3.4], [admin@dns-oarc.net], [dnsperf], [https://github.com/DNS-OARC/dnsperf/issues])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([src/dnsperf.c])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_MACRO_DIR([m4])

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
AC_ARG_WITH([extra-ldflags], [AS_HELP_STRING([--with-extra-ldflags=CFLAGS], [Add extra LDFLAGS])], [
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
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([m], [sqrt])

# Check for OpenSSL
PKG_CHECK_MODULES([libssl], [libssl])
PKG_CHECK_MODULES([libcrypto], [libcrypto]) # also check libcrypto which might be needed for libssl
AC_CHECK_LIB([ssl], [TLS_client_method],
	[AC_DEFINE([HAVE_TLS_CLIENT_METHOD], [1], [Define to 1 if you have the 'TLS_client_method' function])])

# Check for bind
AC_ARG_WITH([bind], [AS_HELP_STRING([--with-bind=PATH], [Specify ISC BIND 9 prefix path])], [
  use_bind="$withval"
],[
  use_bind="yes"
])

AC_MSG_CHECKING([for BIND 9 libraries])
if test $use_bind = no; then
  AC_MSG_ERROR([BIND 9 libraries must be installed])
elif test $use_bind = yes; then
  bindpath="$PATH"
else
  bindpath="$withval/bin"
fi
AC_PATH_PROG(ac_cv_isc_config, [isc-config.sh], [no], [$bindpath])
if test "$ac_cv_isc_config" = "no"; then
# BIND 9.16+
  AC_MSG_NOTICE([Trying BIND 9.16+ workaround...])

  AS_VAR_COPY(old_CFLAGS, CFLAGS)
  AS_VAR_COPY(old_LDFLAGS, LDFLAGS)
  AS_VAR_APPEND(CFLAGS, [" $libssl_CFLAGS $libcrypto_CFLAGS"])
  AS_VAR_APPEND(LDFLAGS, [" $libssl_LIBS $libcrypto_LIBS"])
  AC_CHECK_LIB([xml2], [xmlNewTextWriter])
  AC_CHECK_LIB([json-c], [json_object_new_array])

  AC_CHECK_LIB([isc], [isc_mem_create], [], [AC_MSG_ERROR([Please install BIND9 development files])])
  AC_CHECK_LIB([dns], [dns_name_init], [], [AC_MSG_ERROR([Please install BIND9 development files])])
  AC_CHECK_LIB([bind9], [bind9_getaddresses], [], [AC_MSG_ERROR([Please install BIND9 development files])])
  AC_CHECK_HEADER([isc/result.h], [], [AC_MSG_ERROR([Please install BIND9 header files])])
  AC_CHECK_HEADER([bind9/getaddresses.h], [], [AC_MSG_ERROR([Please install BIND9 header files])])

  AS_VAR_COPY(CFLAGS, old_CFLAGS)
  AS_VAR_COPY(LDFLAGS, old_LDFLAGS)
else
# BIND <= 9.14
  AS_VAR_APPEND(CFLAGS, [" `$ac_cv_isc_config --cflags dns bind9`"])
  AS_VAR_APPEND(LDFLAGS, [" `$ac_cv_isc_config --libs dns bind9`"])
fi

AC_MSG_CHECKING([return type of isc_mem_create])
returns=undefined
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <isc/mem.h>]],
      [[ isc_result_t result = isc_mem_create(0, 0, NULL) ]])],
  [returns=isc_result_t
   AC_DEFINE([HAVE_ISC_MEM_CREATE_RESULT], [1], [Define to 1 if 'isc_mem_create' returns result])],
  [returns=void]
)
AC_MSG_RESULT([$returns])

AC_MSG_CHECKING([return type of isc_buffer_allocate])
returns=undefined
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <isc/buffer.h>]],
      [[ isc_result_t result = isc_buffer_allocate(NULL, NULL, 0) ]])],
  [returns=isc_result_t
   AC_DEFINE([HAVE_ISC_BUFFER_ALLOCATE_RESULT], [1], [Define to 1 if 'isc_buffer_allocate' returns result])],
  [returns=void]
)
AC_MSG_RESULT([$returns])

AC_CHECK_HEADERS([isc/hmacmd5.h isc/hmacsha.h])

# Checks for sizes
AX_TYPE_SOCKLEN_T
AX_SA_LEN

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/test/Makefile
])
AC_OUTPUT
