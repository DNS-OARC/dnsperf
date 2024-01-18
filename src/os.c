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

#include "os.h"

#include "log.h"
#include "util.h"

#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#if defined(HAVE_PTHREAD_NP_H)
#include <pthread_np.h>
#endif /* if defined(HAVE_PTHREAD_NP_H) */

void perf_os_blocksignal(int sig, bool block)
{
    sigset_t sset;
    int      op;

    op = block ? SIG_BLOCK : SIG_UNBLOCK;

    if (sigemptyset(&sset) < 0 || sigaddset(&sset, sig) < 0 || pthread_sigmask(op, &sset, NULL) < 0) {
        char __s[256];
        perf_log_fatal("pthread_sigmask: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }
}

void perf_os_handlesignal(int sig, void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;

    if (sigfillset(&sa.sa_mask) < 0 || sigaction(sig, &sa, NULL) < 0) {
        char __s[256];
        perf_log_fatal("sigaction: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }
}

perf_result_t
perf_os_waituntilreadable(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    struct perf_net_socket* socks[] = { sock };
    return perf_os_waituntilanyreadable(socks, 1, pipe_fd, timeout);
}

perf_result_t
perf_os_waituntilanyreadable(struct perf_net_socket** socks, unsigned int nfds, int pipe_fd,
    int64_t timeout)
{
    struct pollfd fds[nfds + 1];
    size_t        i;
    int           to, n;

    for (i = 0; i < nfds; i++) {
        if (perf_net_have_more(socks[i]))
            return (PERF_R_SUCCESS);

        fds[i].fd     = socks[i]->fd;
        fds[i].events = POLLIN;
    }

    fds[nfds].fd     = pipe_fd;
    fds[nfds].events = POLLIN;

    if (timeout < 0) {
        to = -1;
    } else {
        to = timeout / 1000;
        if (timeout && !to) {
            to = 1;
        }
    }

    n = poll(fds, nfds + 1, to);
    if (n < 0) {
        if (errno != EINTR) {
            char __s[256];
            perf_log_fatal("select(): %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
        return (PERF_R_CANCELED);
    } else if (n == 0) {
        return (PERF_R_TIMEDOUT);
    } else if (fds[nfds].revents & POLLIN) {
        return (PERF_R_CANCELED);
    } else {
        return (PERF_R_SUCCESS);
    }
}

perf_result_t
perf_os_waituntilanywritable(struct perf_net_socket** socks, unsigned int nfds, int pipe_fd,
    int64_t timeout)
{
    struct pollfd fds[nfds + 1];
    size_t        i;
    int           to, n;

    for (i = 0; i < nfds; i++) {
        fds[i].fd     = socks[i]->fd;
        fds[i].events = POLLOUT;
    }

    fds[nfds].fd     = pipe_fd;
    fds[nfds].events = POLLIN;

    if (timeout < 0) {
        to = -1;
    } else {
        to = timeout / 1000;
        if (timeout && !to) {
            to = 1;
        }
    }

    n = poll(fds, nfds + 1, to);
    if (n < 0) {
        if (errno != EINTR) {
            char __s[256];
            perf_log_fatal("select(): %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
        return (PERF_R_CANCELED);
    } else if (n == 0) {
        return (PERF_R_TIMEDOUT);
    } else if (fds[nfds].revents & POLLIN) {
        return (PERF_R_CANCELED);
    } else {
        return (PERF_R_SUCCESS);
    }
}

void perf_os_thread_setname(pthread_t thread, const char* name)
{
#if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__)
    /*
     * macOS has pthread_setname_np but only works on the
     * current thread so it's not used here
     */
#if defined(__NetBSD__)
    (void)pthread_setname_np(thread, name, NULL);
#else /* if defined(__NetBSD__) */
    (void)pthread_setname_np(thread, name);
#endif /* if defined(__NetBSD__) */
#elif defined(HAVE_PTHREAD_SET_NAME_NP)
    (void)pthread_set_name_np(thread, name);
#else /* if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__) */
    (void)(thread);
    (void)(name);
#endif /* if defined(HAVE_PTHREAD_SETNAME_NP) && !defined(__APPLE__) */
}
