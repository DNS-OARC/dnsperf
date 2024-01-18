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

#ifndef PERF_BUFFER_H
#define PERF_BUFFER_H 1

#include <stddef.h>

typedef struct perf_region {
    void*  base;
    size_t length;
} perf_region_t;

typedef struct perf_buffer {
    void*  base;
    size_t length, used, current, active;
} perf_buffer_t;

#include <assert.h>

#define perf_buffer_init(b, _base, _length) \
    {                                       \
        (b)->base    = _base;               \
        (b)->length  = _length;             \
        (b)->used    = 0;                   \
        (b)->current = 0;                   \
        (b)->active  = 0;                   \
    }

#define perf_buffer_add(b, n)                 \
    {                                         \
        assert((b)->used + n <= (b)->length); \
        (b)->used += (n);                     \
    }

#define perf_buffer_length(b) ((b)->length)

#define perf_buffer_availablelength(b) ((b)->length - (b)->used)

#define perf_buffer_base(b) ((b)->base)

#define perf_buffer_clear(b) \
    {                        \
        (b)->used    = 0;    \
        (b)->current = 0;    \
        (b)->active  = 0;    \
    }

#define perf_buffer_putmem(b, base, length)               \
    {                                                     \
        assert(perf_buffer_availablelength(b) >= length); \
        memcpy(perf_buffer_used(b), base, length);        \
        perf_buffer_add(b, length);                       \
    }

#define perf_buffer_putuint8(b, _val)                 \
    {                                                 \
        unsigned char* _cp;                           \
        uint8_t        _val2 = (_val);                \
        assert(perf_buffer_availablelength(b) >= 1U); \
        _cp = perf_buffer_used(b);                    \
        (b)->used += 1U;                              \
        _cp[0] = _val2;                               \
    }

#define perf_buffer_putuint16(b, _val)                \
    {                                                 \
        unsigned char* _cp;                           \
        uint16_t       _val2 = (_val);                \
        assert(perf_buffer_availablelength(b) >= 2U); \
        _cp = perf_buffer_used(b);                    \
        (b)->used += 2U;                              \
        _cp[0] = _val2 >> 8;                          \
        _cp[1] = _val2;                               \
    }

#define perf_buffer_putuint32(b, _val)                \
    {                                                 \
        unsigned char* _cp;                           \
        uint32_t       _val2 = (_val);                \
        assert(perf_buffer_availablelength(b) >= 4U); \
        _cp = perf_buffer_used(b);                    \
        (b)->used += 4U;                              \
        _cp[0] = _val2 >> 24;                         \
        _cp[1] = _val2 >> 16;                         \
        _cp[2] = _val2 >> 8;                          \
        _cp[3] = _val2;                               \
    }

#define perf_buffer_copyregion(b, r) perf_buffer_putmem(b, (r)->base, (r)->length)

#define perf_buffer_used(b) ((void*)((unsigned char*)(b)->base + (b)->used))
#define perf_buffer_usedlength(b) ((b)->used)
#define perf_buffer_usedregion(b, r) \
    {                                \
        (r)->base   = (b)->base;     \
        (r)->length = (b)->used;     \
    }

#endif
