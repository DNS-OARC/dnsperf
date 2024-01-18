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

#include "net.h"

#include "log.h"
#include "strerror.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define self ((struct perf__udp_socket*)sock)

struct perf__udp_socket {
    struct perf_net_socket base;
};

static ssize_t perf__udp_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    return recv(sock->fd, buf, len, flags);
}

static ssize_t perf__udp_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    return sendto(sock->fd, buf, len, flags, dest_addr, addrlen);
}

static int perf__udp_close(struct perf_net_socket* sock)
{
    return close(sock->fd);
}

static int perf__udp_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    return sock_a->fd == sock_b->fd;
}

static int perf__udp_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    return 1;
}

struct perf_net_socket* perf_net_udp_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event)
{
    struct perf__udp_socket* tmp  = calloc(1, sizeof(struct perf__udp_socket)); // clang scan-build
    struct perf_net_socket*  sock = (struct perf_net_socket*)tmp;

    int ret, flags;

    if (!sock) {
        perf_log_fatal("perf_net_udp_opensocket() out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__udp_recv;
    sock->sendto    = perf__udp_sendto;
    sock->close     = perf__udp_close;
    sock->sockeq    = perf__udp_sockeq;
    sock->sockready = perf__udp_sockready;

    sock->data  = data;
    sock->sent  = sent;
    sock->event = event;

    sock->fd = socket(server->sa.sa.sa_family, SOCK_DGRAM, 0);
    if (sock->fd == -1) {
        char __s[256];
        perf_log_fatal("socket: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (server->sa.sa.sa_family == AF_INET6) {
        int on = 1;

        if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
            perf_log_warning("setsockopt(IPV6_V6ONLY) failed");
        }
    }

    if (bind(sock->fd, &local->sa.sa, local->length) == -1) {
        char __s[256];
        perf_log_fatal("bind: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (bufsize > 0) {
        bufsize *= 1024;

        ret = setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF,
            &bufsize, sizeof(bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_RCVBUF) failed");

        ret = setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF,
            &bufsize, sizeof(bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_SNDBUF) failed");
    }

    flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0)
        perf_log_fatal("fcntl(F_GETFL)");
    ret = fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
        perf_log_fatal("fcntl(F_SETFL)");

    return sock;
}
