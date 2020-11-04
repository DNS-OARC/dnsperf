/*
 * Copyright 2019-2020 OARC, Inc.
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

#ifndef PERF_RESULT_H
#define PERF_RESULT_H 1

#include <isc/result.h>
#include <assert.h>

typedef unsigned int perf_result_t;

#define PERF_R_CANCELED ISC_R_CANCELED
#define PERF_R_EOF ISC_R_EOF
#define PERF_R_FAILURE ISC_R_FAILURE
#define PERF_R_INVALIDFILE ISC_R_INVALIDFILE
#define PERF_R_NOMORE ISC_R_NOMORE
#define PERF_R_NOSPACE ISC_R_NOSPACE
#define PERF_R_SUCCESS ISC_R_SUCCESS
#define PERF_R_TIMEDOUT ISC_R_TIMEDOUT

#define perf_result_totext(r) isc_result_totext(r)

static inline perf_result_t isc2perf_result(isc_result_t r) {
    switch (r) {
        case ISC_R_CANCELED:
        case ISC_R_EOF:
        case ISC_R_FAILURE:
        case ISC_R_INVALIDFILE:
        case ISC_R_NOMORE:
        case ISC_R_NOSPACE:
        case ISC_R_SUCCESS:
        case ISC_R_TIMEDOUT:
            return (perf_result_t)r;
        default:
            assert(0);
    }
}

#endif
