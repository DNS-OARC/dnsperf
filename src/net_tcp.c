/*
 * Copyright 2019-2021 OARC, Inc.
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
#include "os.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define self ((struct perf__tcp_socket*)sock)

struct perf__tcp_socket {
    struct perf_net_socket base;

    char   recvbuf[TCP_RECV_BUF_SIZE], sendbuf[TCP_SEND_BUF_SIZE];
    size_t at, sending;
    bool   is_ready;

    int                     flags;
    struct sockaddr_storage dest_addr;
    socklen_t               addrlen;
};

static ssize_t perf__tcp_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    ssize_t  n;
    uint16_t dnslen, dnslen2;

    if (!sock->have_more) {
        n = recv(sock->fd, self->recvbuf + self->at, TCP_RECV_BUF_SIZE - self->at, flags);
        if (n < 0) {
            if (errno == ECONNRESET) {
                // Treat connection reset like try again until reconnection features are in
                errno = EAGAIN;
            }
            return n;
        }
        self->at += n;
        if (self->at < 3) {
            errno = EAGAIN;
            return -1;
        }
    }

    memcpy(&dnslen, self->recvbuf, 2);
    dnslen = ntohs(dnslen);
    if (self->at < dnslen + 2) {
        errno = EAGAIN;
        return -1;
    }
    memcpy(buf, self->recvbuf + 2, len < dnslen ? len : dnslen);
    memmove(self->recvbuf, self->recvbuf + 2 + dnslen, self->at - 2 - dnslen);
    self->at -= 2 + dnslen;

    if (self->at > 2) {
        memcpy(&dnslen2, self->recvbuf, 2);
        dnslen2 = ntohs(dnslen2);
        if (self->at >= dnslen2 + 2) {
            sock->have_more = true;
            return dnslen;
        }
    }

    sock->have_more = false;
    return dnslen;
}

static ssize_t perf__tcp_sendto(struct perf_net_socket* sock, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    size_t send = len < TCP_SEND_BUF_SIZE - 2 ? len : (TCP_SEND_BUF_SIZE - 2);
    // TODO: We only send what we can send, because we can't continue sending
    uint16_t dnslen = htons(send);
    ssize_t  n;

    memcpy(self->sendbuf, &dnslen, 2);
    memcpy(self->sendbuf + 2, buf, send);
    n = sendto(sock->fd, self->sendbuf, send + 2, flags, dest_addr, addrlen);

    if (n > 0 && n < send + 2) {
        sock->is_sending = true;
        self->sending    = n;
        self->flags      = flags;
        memcpy(&self->dest_addr, dest_addr, addrlen);
        self->addrlen  = addrlen;
        self->is_ready = false;
        errno          = EINPROGRESS;
        return -1;
    }

    return n > 0 ? n - 2 : n;
}

static int perf__tcp_close(struct perf_net_socket* sock)
{
    return close(sock->fd);
}

static int perf__tcp_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    return sock_a->fd == sock_b->fd;
}

static int perf__tcp_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    if (self->is_ready) {
        return 1;
    }

    if (self->sending) {
        uint16_t dnslen;
        ssize_t  n;

        memcpy(&dnslen, self->sendbuf, 2);
        dnslen = ntohs(dnslen);
        n      = sendto(sock->fd, self->sendbuf + self->sending, dnslen + 2 - self->sending, self->flags, (struct sockaddr*)&self->dest_addr, self->addrlen);
        if (n < 1) {
            return -1;
        }
        self->sending += n;
        if (self->sending < dnslen + 2) {
            errno = EINPROGRESS;
            return -1;
        }
        self->sending    = 0;
        sock->is_sending = false;
        self->is_ready   = true;
        return 1;
    }

    switch (perf_os_waituntilanywritable(&sock, 1, pipe_fd, timeout)) {
    case PERF_R_TIMEDOUT:
        return -1;
    case PERF_R_SUCCESS: {
        int       error = 0;
        socklen_t len   = (socklen_t)sizeof(error);

        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, (void*)&error, &len);
        if (error != 0) {
            if (error == EINPROGRESS
#if EWOULDBLOCK != EAGAIN
                || error == EWOULDBLOCK
#endif
                || error == EAGAIN) {
                return 0;
            }
            return -1;
        }
        self->is_ready = true;
        return 1;
    }
    default:
        break;
    }

    return -1;
}

struct perf_net_socket* perf_net_tcp_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize)
{
    struct perf__tcp_socket* tmp = calloc(1, sizeof(struct perf__tcp_socket)); // clang scan-build
    struct perf_net_socket* sock = (struct perf_net_socket*)tmp;

    int ret, flags;

    if (!sock) {
        perf_log_fatal("perf_net_tcp_opensocket() out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__tcp_recv;
    sock->sendto    = perf__tcp_sendto;
    sock->close     = perf__tcp_close;
    sock->sockeq    = perf__tcp_sockeq;
    sock->sockready = perf__tcp_sockready;

    self->is_ready = true;

    sock->fd = socket(server->sa.sa.sa_family, SOCK_STREAM, 0);
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

    if (connect(sock->fd, &server->sa.sa, server->length)) {
        if (errno == EINPROGRESS) {
            self->is_ready = false;
        } else {
            char __s[256];
            perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }

    return sock;
}
