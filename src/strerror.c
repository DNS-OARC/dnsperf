/*
 * Copyright 2019-2024 OARC, Inc.
 * Copyright 2017-2018 Akamai Technologies
 * Copyright 2006-2016 Nominum, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include "strerror.h"

#include <string.h>
#include <stdio.h>

const char* perf_strerror_r(int errnum, char* str, size_t len)
{
#if ((_POSIX_C_SOURCE >= 200112L) && !_GNU_SOURCE) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
    if (strerror_r(errnum, str, len)) {
        (void)snprintf(str, len, "Error %d", errnum);
    }
    return str;
#else
    return strerror_r(errnum, str, len);
#endif
}
