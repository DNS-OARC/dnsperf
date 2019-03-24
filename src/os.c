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

#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>

#include <isc/result.h>
#include <isc/types.h>

#include "log.h"
#include "os.h"
#include "util.h"

void perf_os_blocksignal(int sig, bool block)
{
    sigset_t sset;
    int      op;

    op = block ? SIG_BLOCK : SIG_UNBLOCK;

    if (sigemptyset(&sset) < 0 || sigaddset(&sset, sig) < 0 || pthread_sigmask(op, &sset, NULL) < 0) {
        perf_log_fatal("pthread_sigmask: %s", strerror(errno));
    }
}

void perf_os_handlesignal(int sig, void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;

    if (sigfillset(&sa.sa_mask) < 0 || sigaction(sig, &sa, NULL) < 0) {
        perf_log_fatal("sigaction: %s", strerror(errno));
    }
}

isc_result_t
perf_os_waituntilreadable(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    return perf_os_waituntilanyreadable(sock, 1, pipe_fd, timeout);
}

isc_result_t
perf_os_waituntilanyreadable(struct perf_net_socket* socks, unsigned int nfds, int pipe_fd,
    int64_t timeout)
{
    fd_set         read_fds;
    unsigned int   i;
    int            maxfd;
    struct timeval tv, *tvp;
    int            n;

    FD_ZERO(&read_fds);
    maxfd = 0;
    for (i = 0; i < nfds; i++) {
        if (socks[i].have_more)
            return (ISC_R_SUCCESS);
        FD_SET(socks[i].fd, &read_fds);
        if (socks[i].fd > maxfd)
            maxfd = socks[i].fd;
    }
    FD_SET(pipe_fd, &read_fds);
    if (pipe_fd > maxfd)
        maxfd = pipe_fd;

    if (timeout < 0) {
        tvp = NULL;
    } else {
        tv.tv_sec  = timeout / MILLION;
        tv.tv_usec = timeout % MILLION;
        tvp        = &tv;
    }
    n = select(maxfd + 1, &read_fds, NULL, NULL, tvp);
    if (n < 0) {
        if (errno != EINTR)
            perf_log_fatal("select(): %s", strerror(errno));
        return (ISC_R_CANCELED);
    } else if (n == 0) {
        return (ISC_R_TIMEDOUT);
    } else if (FD_ISSET(pipe_fd, &read_fds)) {
        return (ISC_R_CANCELED);
    } else {
        return (ISC_R_SUCCESS);
    }
}

isc_result_t
perf_os_waituntilanywritable(struct perf_net_socket* socks, unsigned int nfds, int pipe_fd,
    int64_t timeout)
{
    fd_set         write_fds, read_fds;
    unsigned int   i;
    int            maxfd;
    struct timeval tv, *tvp;
    int            n;

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    maxfd = 0;
    for (i = 0; i < nfds; i++) {
        FD_SET(socks[i].fd, &write_fds);
        if (socks[i].fd > maxfd)
            maxfd = socks[i].fd;
    }
    FD_SET(pipe_fd, &read_fds);
    if (pipe_fd > maxfd)
        maxfd = pipe_fd;

    if (timeout < 0) {
        tvp = NULL;
    } else {
        tv.tv_sec  = timeout / MILLION;
        tv.tv_usec = timeout % MILLION;
        tvp        = &tv;
    }
    n = select(maxfd + 1, &read_fds, &write_fds, NULL, tvp);
    if (n < 0) {
        if (errno != EINTR)
            perf_log_fatal("select(): %s", strerror(errno));
        return (ISC_R_CANCELED);
    } else if (n == 0) {
        return (ISC_R_TIMEDOUT);
    } else if (FD_ISSET(pipe_fd, &read_fds)) {
        return (ISC_R_CANCELED);
    } else {
        return (ISC_R_SUCCESS);
    }
}
