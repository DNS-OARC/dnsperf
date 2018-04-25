/*
 * Copyright (C) 2011-2015 Nominum, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "util.h"

pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void
vlog(FILE *stream, const char *prefix, const char term, const char *fmt, va_list args)
{
    LOCK(&log_lock);
    fflush(stdout);
    if (prefix != NULL)
        fprintf(stream, "%s: ", prefix);
    vfprintf(stream, fmt, args);
    fprintf(stream, "%c", term);
    UNLOCK(&log_lock);
}

void
perf_log_sameline(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vlog(stderr, NULL, '\r', fmt, args);
}

void
perf_log_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vlog(stdout, NULL, '\n', fmt, args);
}

void
perf_log_fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vlog(stderr, "Error", '\n', fmt, args);
    exit(1);
}

void
perf_log_warning(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vlog(stderr, "Warning", '\n', fmt, args);
}
