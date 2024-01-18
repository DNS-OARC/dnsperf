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

#ifndef PERF_LIST_H
#define PERF_LIST_H 1

#include <assert.h>

#define perf_link(type)    \
    struct {               \
        type *prev, *next; \
    } _link
#define perf_link_init(link)    \
    {                           \
        (link)->_link.prev = 0; \
        (link)->_link.next = 0; \
    }

#define perf_list(type)    \
    struct {               \
        type *head, *tail; \
    }
#define perf_list_init(list) \
    {                        \
        (list).head = 0;     \
        (list).tail = 0;     \
    }

#define perf_list_head(list) ((list).head)
#define perf_list_tail(list) ((list).tail)
#define perf_list_empty(list) (!(list).head)

#define perf_list_append(list, link)          \
    {                                         \
        if ((list).tail) {                    \
            (list).tail->_link.next = (link); \
        } else {                              \
            (list).head = (link);             \
        }                                     \
        (link)->_link.prev = (list).tail;     \
        (link)->_link.next = 0;               \
        (list).tail        = (link);          \
    }
#define perf_list_prepend(list, link)         \
    {                                         \
        if ((list).head) {                    \
            (list).head->_link.prev = (link); \
        } else {                              \
            (list).tail = (link);             \
        }                                     \
        (link)->_link.prev = 0;               \
        (link)->_link.next = (list).head;     \
        (list).head        = (link);          \
    }
#define perf_list_unlink(list, link)                             \
    {                                                            \
        if ((link)->_link.next) {                                \
            (link)->_link.next->_link.prev = (link)->_link.prev; \
        } else {                                                 \
            assert((list).tail == (link));                       \
            (list).tail = (link)->_link.prev;                    \
        }                                                        \
        if ((link)->_link.prev) {                                \
            (link)->_link.prev->_link.next = (link)->_link.next; \
        } else {                                                 \
            assert((list).head == (link));                       \
            (list).head = (link)->_link.next;                    \
        }                                                        \
        (link)->_link.next = 0;                                  \
        (link)->_link.prev = 0;                                  \
        assert((list).head != (link));                           \
        assert((list).tail != (link));                           \
    }

#endif
