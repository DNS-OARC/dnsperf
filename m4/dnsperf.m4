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

AC_DEFUN([AX_TYPE_SOCKLEN_T],
[AC_CACHE_CHECK([for socklen_t], ac_cv_type_socklen_t,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>],
  [socklen_t len = 42; return len;],
  ac_cv_type_socklen_t=yes,
  ac_cv_type_socklen_t=no)
])
  if test $ac_cv_type_socklen_t != yes; then
    AC_DEFINE([socklen_t], [int], [The type of socklen_t.])
  fi
])

AC_DEFUN([AX_SA_LEN],
[AC_CACHE_CHECK([for sa_len], ac_cv_sa_len,
[
  AC_TRY_COMPILE(
  [#include <sys/types.h>
   #include <sys/socket.h>],
  [struct sockaddr sa; sa.sa_len = 0;],
  ac_cv_sa_len=yes,
  ac_cv_sa_len=no)
])
  if test $ac_cv_sa_len = yes; then
    AC_DEFINE([HAVE_SA_LEN], [1], [Set if struct sockaddr sa_len exists.])
  fi
])
