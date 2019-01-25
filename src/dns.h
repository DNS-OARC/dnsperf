/*
 * Copyright 2019 OARC, Inc.
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

#include <isc/types.h>

#ifndef PERF_DNS_H
#define PERF_DNS_H 1

#define MAX_UDP_PACKET 512
#define MAX_EDNS_PACKET 4096

typedef struct perf_dnstsigkey    perf_dnstsigkey_t;
typedef struct perf_dnsednsoption perf_dnsednsoption_t;
typedef struct perf_dnsctx        perf_dnsctx_t;

extern const char* perf_dns_rcode_strings[];

perf_dnstsigkey_t*
perf_dns_parsetsigkey(const char* arg, isc_mem_t* mctx);

void perf_dns_destroytsigkey(perf_dnstsigkey_t** tsigkeyp);

perf_dnsednsoption_t*
perf_dns_parseednsoption(const char* arg, isc_mem_t* mctx);

void perf_dns_destroyednsoption(perf_dnsednsoption_t** optionp);

perf_dnsctx_t*
perf_dns_createctx(bool updates);

void perf_dns_destroyctx(perf_dnsctx_t** ctxp);

isc_result_t
perf_dns_buildrequest(perf_dnsctx_t* ctx, const isc_textregion_t* record,
    uint16_t qid,
    bool edns, bool dnssec,
    perf_dnstsigkey_t*    tsigkey,
    perf_dnsednsoption_t* edns_option, isc_buffer_t* msg);

#endif
