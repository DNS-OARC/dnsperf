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

#include "log.h"
#include "strerror.h"

#ifndef PERF_UTIL_H
#define PERF_UTIL_H 1

#include <pthread.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#define MILLION ((uint64_t)1000000)

#define PERF_THREAD(thread, start, arg)                                                          \
    do {                                                                                         \
        int __n = pthread_create((thread), NULL, (start), (arg));                                \
        if (__n != 0) {                                                                          \
            char __s[256];                                                                       \
            perf_log_fatal("pthread_create failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                        \
    } while (0)

#define PERF_JOIN(thread, valuep)                                                              \
    do {                                                                                       \
        int __n = pthread_join((thread), (valuep));                                            \
        if (__n != 0) {                                                                        \
            char __s[256];                                                                     \
            perf_log_fatal("pthread_join failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                      \
    } while (0)

#define PERF_MUTEX_INIT(mutex)                                                                       \
    do {                                                                                             \
        int __n = pthread_mutex_init((mutex), NULL);                                                 \
        if (__n != 0) {                                                                              \
            char __s[256];                                                                           \
            perf_log_fatal("pthread_mutex_init failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                            \
    } while (0)

#define PERF_MUTEX_DESTROY(mutex)                                                                       \
    do {                                                                                                \
        int __n = pthread_mutex_destroy((mutex));                                                       \
        if (__n != 0) {                                                                                 \
            char __s[256];                                                                              \
            perf_log_fatal("pthread_mutex_destroy failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                               \
    } while (0)

#define PERF_LOCK(mutex)                                                                             \
    do {                                                                                             \
        int __n = pthread_mutex_lock((mutex));                                                       \
        if (__n != 0) {                                                                              \
            char __s[256];                                                                           \
            perf_log_fatal("pthread_mutex_lock failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                            \
    } while (0)

static inline int PERF_TRYLOCK(pthread_mutex_t* mutex)
{
    int __n = pthread_mutex_trylock(mutex);
    if (__n == EBUSY) {
        return 1;
    }
    if (__n != 0) {
        char __s[256];
        perf_log_fatal("pthread_mutex_lock failed: %s", perf_strerror_r(__n, __s, sizeof(__s)));
    }
    return 0;
}

#define PERF_UNLOCK(mutex)                                                                             \
    do {                                                                                               \
        int __n = pthread_mutex_unlock((mutex));                                                       \
        if (__n != 0) {                                                                                \
            char __s[256];                                                                             \
            perf_log_fatal("pthread_mutex_unlock failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                              \
    } while (0)

#define PERF_COND_INIT(cond)                                                                        \
    do {                                                                                            \
        int __n = pthread_cond_init((cond), NULL);                                                  \
        if (__n != 0) {                                                                             \
            char __s[256];                                                                          \
            perf_log_fatal("pthread_cond_init failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                           \
    } while (0)

#define PERF_SIGNAL(cond)                                                                             \
    do {                                                                                              \
        int __n = pthread_cond_signal((cond));                                                        \
        if (__n != 0) {                                                                               \
            char __s[256];                                                                            \
            perf_log_fatal("pthread_cond_signal failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                             \
    } while (0)

#define PERF_BROADCAST(cond)                                                                             \
    do {                                                                                                 \
        int __n = pthread_cond_broadcast((cond));                                                        \
        if (__n != 0) {                                                                                  \
            char __s[256];                                                                               \
            perf_log_fatal("pthread_cond_broadcast failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                                \
    } while (0)

#define PERF_WAIT(cond, mutex)                                                                      \
    do {                                                                                            \
        int __n = pthread_cond_wait((cond), (mutex));                                               \
        if (__n != 0) {                                                                             \
            char __s[256];                                                                          \
            perf_log_fatal("pthread_cond_wait failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                           \
    } while (0)

#define PERF_TIMEDWAIT(cond, mutex, when, timedout)                                                      \
    do {                                                                                                 \
        int   __n = pthread_cond_timedwait((cond), (mutex), (when));                                     \
        bool* res = (timedout);                                                                          \
        if (__n != 0 && __n != ETIMEDOUT) {                                                              \
            char __s[256];                                                                               \
            perf_log_fatal("pthread_cond_timedwait failed: %s", perf_strerror_r(__n, __s, sizeof(__s))); \
        }                                                                                                \
        if (res != NULL) {                                                                               \
            *res = (__n != 0);                                                                           \
        }                                                                                                \
    } while (0)

static __inline__ uint64_t perf_get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * MILLION + tv.tv_usec;
}

#define PERF_SAFE_DIV(n, d) ((d) == 0 ? 0 : (n) / (d))

#endif
