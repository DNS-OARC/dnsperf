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

#ifndef PERF_OS_H
#define PERF_OS_H 1

void
perf_os_blocksignal(int sig, isc_boolean_t block);

void
perf_os_handlesignal(int sig, void (*handler)(int));

isc_result_t
perf_os_waituntilreadable(int fd, int pipe_fd, isc_int64_t timeout);

isc_result_t
perf_os_waituntilanyreadable(int *fds, unsigned int nfds, int pipe_fd,
                             isc_int64_t timeout);

#endif
