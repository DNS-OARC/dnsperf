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

#include "net.h"

#ifndef PERF_OS_H
#define PERF_OS_H 1

#include <inttypes.h>
#include <stdbool.h>

void perf_os_blocksignal(int sig, bool block);

void perf_os_handlesignal(int sig, void (*handler)(int));

isc_result_t
perf_os_waituntilreadable(struct perf_net_socket* sock, int pipe_fd, int64_t timeout);

isc_result_t
perf_os_waituntilanyreadable(struct perf_net_socket* socks, unsigned int nfds, int pipe_fd,
    int64_t timeout);

isc_result_t
perf_os_waituntilanywritable(struct perf_net_socket* socks, unsigned int nfds, int pipe_fd,
    int64_t timeout);

#endif
