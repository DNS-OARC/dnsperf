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

#include <pthread.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include <sys/time.h>

#include <isc/types.h>

#include "log.h"

#ifndef PERF_UTIL_H
#define PERF_UTIL_H 1

#define MILLION ((uint64_t)1000000)

#define THREAD(thread, start, arg)                                      \
    do {                                                                \
        int __n = pthread_create((thread), NULL, (start), (arg));       \
        if (__n != 0) {                                                 \
            perf_log_fatal("pthread_create failed: %s", strerror(__n)); \
        }                                                               \
    } while (0)

#define JOIN(thread, valuep)                                          \
    do {                                                              \
        int __n = pthread_join((thread), (valuep));                   \
        if (__n != 0) {                                               \
            perf_log_fatal("pthread_join failed: %s", strerror(__n)); \
        }                                                             \
    } while (0)

#define MUTEX_INIT(mutex)                                                   \
    do {                                                                    \
        int __n = pthread_mutex_init((mutex), NULL);                        \
        if (__n != 0) {                                                     \
            perf_log_fatal("pthread_mutex_init failed: %s", strerror(__n)); \
        }                                                                   \
    } while (0)

#define MUTEX_DESTROY(mutex)                                                   \
    do {                                                                       \
        int __n = pthread_mutex_destroy((mutex));                              \
        if (__n != 0) {                                                        \
            perf_log_fatal("pthread_mutex_destroy failed: %s", strerror(__n)); \
        }                                                                      \
    } while (0)

#define LOCK(mutex)                                                         \
    do {                                                                    \
        int __n = pthread_mutex_lock((mutex));                              \
        if (__n != 0) {                                                     \
            perf_log_fatal("pthread_mutex_lock failed: %s", strerror(__n)); \
        }                                                                   \
    } while (0)

#define UNLOCK(mutex)                                                         \
    do {                                                                      \
        int __n = pthread_mutex_unlock((mutex));                              \
        if (__n != 0) {                                                       \
            perf_log_fatal("pthread_mutex_unlock failed: %s", strerror(__n)); \
        }                                                                     \
    } while (0)

#define COND_INIT(cond)                                                    \
    do {                                                                   \
        int __n = pthread_cond_init((cond), NULL);                         \
        if (__n != 0) {                                                    \
            perf_log_fatal("pthread_cond_init failed: %s", strerror(__n)); \
        }                                                                  \
    } while (0)

#define SIGNAL(cond)                                                         \
    do {                                                                     \
        int __n = pthread_cond_signal((cond));                               \
        if (__n != 0) {                                                      \
            perf_log_fatal("pthread_cond_signal failed: %s", strerror(__n)); \
        }                                                                    \
    } while (0)

#define BROADCAST(cond)                                                         \
    do {                                                                        \
        int __n = pthread_cond_broadcast((cond));                               \
        if (__n != 0) {                                                         \
            perf_log_fatal("pthread_cond_broadcast failed: %s", strerror(__n)); \
        }                                                                       \
    } while (0)

#define WAIT(cond, mutex)                                                  \
    do {                                                                   \
        int __n = pthread_cond_wait((cond), (mutex));                      \
        if (__n != 0) {                                                    \
            perf_log_fatal("pthread_cond_wait failed: %s", strerror(__n)); \
        }                                                                  \
    } while (0)

#define TIMEDWAIT(cond, mutex, when, timedout)                                  \
    do {                                                                        \
        int   __n = pthread_cond_timedwait((cond), (mutex), (when));            \
        bool* res = (timedout);                                                 \
        if (__n != 0 && __n != ETIMEDOUT) {                                     \
            perf_log_fatal("pthread_cond_timedwait failed: %s", strerror(__n)); \
        }                                                                       \
        if (res != NULL) {                                                      \
            *res = (__n != 0);                                                  \
        }                                                                       \
    } while (0)

static __inline__ uint64_t
get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * MILLION + tv.tv_usec;
}

#define SAFE_DIV(n, d) ((d) == 0 ? 0 : (n) / (d))

#endif
