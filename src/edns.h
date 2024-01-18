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

#include "result.h"
#include "buffer.h"

#ifndef PERF_EDNS_H
#define PERF_EDNS_H 1

#include <stdbool.h>

#define MAX_EDNS_PACKET 4096

typedef struct perf_ednsoption {
    perf_buffer_t buffer;
    char          data[];
} perf_ednsoption_t;

perf_ednsoption_t* perf_edns_parseoption(const char* arg);

void perf_edns_destroyoption(perf_ednsoption_t** optionp);

perf_result_t perf_add_edns(perf_buffer_t* packet, bool dnssec, perf_ednsoption_t* option);

#endif
