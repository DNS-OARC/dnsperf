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

#ifndef PERF_RESULT_H
#define PERF_RESULT_H 1

#include <assert.h>

typedef unsigned int perf_result_t;

#define PERF_R_SUCCESS 0
#define PERF_R_FAILURE 1
#define PERF_R_CANCELED 2
#define PERF_R_EOF 3
#define PERF_R_INVALIDFILE 4
#define PERF_R_NOMORE 5
#define PERF_R_NOSPACE 6
#define PERF_R_TIMEDOUT 7

#define PERF_R_INVALIDUPDATE 100

#endif
