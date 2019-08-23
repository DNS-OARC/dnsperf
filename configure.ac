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

AC_PREREQ(2.64)
AC_INIT([dnsperf], [2.3.2], [admin@dns-oarc.net], [dnsperf], [https://github.com/DNS-OARC/dnsperf/issues])
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

# Checks for support.
AX_PTHREAD
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([nsl], [inet_ntoa])
AC_CHECK_LIB([m], [sqrt])

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
  AC_MSG_ERROR([BIND 9 libraries must be installed])
fi

case "$host_os" in
  freebsd*)
    AC_MSG_NOTICE([Add workaround for FreeBSD by using static libcrypto])
    AS_VAR_APPEND(LDFLAGS, [" /usr/lib/libcrypto.a"])
    ;;
esac

AS_VAR_APPEND(CFLAGS, [" `$ac_cv_isc_config --cflags dns bind9`"])
AS_VAR_APPEND(LDFLAGS, [" `$ac_cv_isc_config --libs dns bind9`"])

AC_CHECK_HEADERS([isc/hmacmd5.h isc/hmacsha.h])

# Check for OpenSSL
PKG_CHECK_MODULES([libssl], [libssl])
AC_CHECK_LIB([ssl], [TLS_client_method],
	[AC_DEFINE([HAVE_TLS_CLIENT_METHOD], [1], [Define to 1 if you have the `TLS_client_method' function])])

# Checks for sizes
AX_TYPE_SOCKLEN_T
AX_SA_LEN

# Output Makefiles
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
