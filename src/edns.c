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

#include "edns.h"

#include "log.h"
#include "opt.h"

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#define EDNSLEN 11

perf_ednsoption_t* perf_edns_parseoption(const char* arg)
{
    char *             copy, *sep, *value, *endptr, hex[3];
    perf_ednsoption_t* option;
    size_t             data_len;
    unsigned long int  u;
    perf_buffer_t      save;

    copy = strdup(arg);
    if (!copy) {
        perf_log_fatal("out of memory");
        return 0; // fix clang scan-build
    }

    sep = strchr(copy, ':');
    if (!sep) {
        perf_log_warning("invalid EDNS Option, must be code:value");
        perf_opt_usage();
        exit(1);
    }
    *sep  = '\0';
    value = sep + 1;

    data_len = strlen(value);
    if (!data_len) {
        perf_log_warning("invalid EDNS Option, value is empty");
        perf_opt_usage();
        exit(1);
    }
    if (data_len & 1) {
        perf_log_warning("invalid EDNS Option, value must hex string (even number of characters)");
        perf_opt_usage();
        exit(1);
    }
    data_len /= 2;
    data_len += 4; // code, len, data...

    option = calloc(1, sizeof(perf_ednsoption_t) + data_len);
    if (!option) {
        perf_log_fatal("out of memory");
        free(copy); // fix clang scan-build
        return 0; // fix clang scan-build
    }
    perf_buffer_init(&option->buffer, &option->data[0], data_len);

    endptr = 0;
    u      = strtoul(copy, &endptr, 10);
    if (*endptr || u == ULONG_MAX) {
        perf_log_warning("invalid EDNS Option code '%s'", copy);
        perf_opt_usage();
        exit(1);
    }
    perf_buffer_putuint16(&option->buffer, u & 0xffff);

    save = option->buffer;
    perf_buffer_add(&option->buffer, 2);
    hex[2] = 0;
    while (*value) {
        memcpy(hex, value, 2);
        endptr = 0;
        u      = strtoul(hex, &endptr, 16);
        if (*endptr || u == ULONG_MAX) {
            perf_log_warning("invalid EDNS Option hex value '%.*s'", 2, value);
            perf_opt_usage();
            exit(1);
        }
        perf_buffer_putuint8(&option->buffer, u & 0xff);
        value += 2;
    }
    perf_buffer_putuint16(&save, perf_buffer_usedlength(&option->buffer) - 4);

    free(copy);

    return option;
}

void perf_edns_destroyoption(perf_ednsoption_t** optionp)
{
    assert(optionp);
    assert(*optionp);

    free(*optionp);
    *optionp = 0;
}

/*
 * Appends an OPT record to the packet.
 */
perf_result_t perf_add_edns(perf_buffer_t* packet, bool dnssec, perf_ednsoption_t* option)
{
    unsigned char* base;
    size_t         option_length = 0, total_length;

    if (option) {
        option_length = perf_buffer_usedlength(&option->buffer);
    }
    total_length = EDNSLEN + option_length;

    if (perf_buffer_availablelength(packet) < total_length) {
        perf_log_warning("failed to add OPT to query packet");
        return PERF_R_NOSPACE;
    }

    base = perf_buffer_base(packet);

    perf_buffer_putuint8(packet, 0); /* root name */
    perf_buffer_putuint16(packet, 41); /* OPT record */
    perf_buffer_putuint16(packet, MAX_EDNS_PACKET); /* class */
    perf_buffer_putuint8(packet, 0); /* xrcode */
    perf_buffer_putuint8(packet, 0); /* version */
    if (dnssec) {
        /* flags */
        perf_buffer_putuint16(packet, 0x8000);
    } else {
        perf_buffer_putuint16(packet, 0);
    }
    perf_buffer_putuint16(packet, option_length); /* rdlen */
    if (option) {
        perf_buffer_putmem(packet, perf_buffer_base(&option->buffer), option_length);
    }

    base[11]++; /* increment additional record count */

    return PERF_R_SUCCESS;
}
