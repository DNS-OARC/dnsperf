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
#include "edns.h"
#include "tsig.h"

#ifndef PERF_DNS_H
#define PERF_DNS_H 1

#include <stdint.h>
#include <stdbool.h>

#define MAX_UDP_PACKET 512

extern const char* perf_dns_rcode_strings[];

perf_result_t perf_dname_fromstring(const char* str, size_t len, perf_buffer_t* target);
perf_result_t perf_qtype_fromstring(const char* str, size_t len, perf_buffer_t* target);

perf_result_t perf_dns_buildrequest(const perf_region_t* record, uint16_t qid,
    bool edns, bool dnssec, bool is_update,
    perf_tsigkey_t* tsigkey, perf_ednsoption_t* edns_option,
    perf_buffer_t* msg);

#endif
