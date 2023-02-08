/*
 * Copyright 2019-2023 OARC, Inc.
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

#ifndef PERF_TSIG_H
#define PERF_TSIG_H 1

#include <openssl/hmac.h>

typedef struct perf_tsigkey {
    char        name[256];
    size_t      namelen, alglen;
    const char* alg;
    HMAC_CTX*   hmac;
} perf_tsigkey_t;

perf_tsigkey_t* perf_tsig_parsekey(const char* arg);

void perf_tsig_destroykey(perf_tsigkey_t** tsigkeyp);

perf_result_t perf_add_tsig(perf_buffer_t* packet, perf_tsigkey_t* tsigkey);

#endif
