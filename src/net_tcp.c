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
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ck_pr.h>

#define self ((struct perf__tcp_socket*)sock)

struct perf__tcp_socket {
    struct perf_net_socket base;

    char   recvbuf[TCP_RECV_BUF_SIZE], sendbuf[TCP_SEND_BUF_SIZE];
    size_t at, sending;
    bool   is_ready, need_reconnect, have_more, is_sending;

    int                     flags;
    struct sockaddr_storage dest_addr;
    socklen_t               addrlen;

    perf_sockaddr_t server, local;
    size_t          bufsize;

    int recvfd;

    uint16_t qid;

    uint64_t            conn_ts;
    perf_socket_event_t conn_event;
};

static int perf__tcp_connect(struct perf_net_socket* sock)
{
    int fd;

    self->is_ready = true;

    fd = socket(self->server.sa.sa.sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        char __s[256];
        perf_log_fatal("socket: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (self->server.sa.sa.sa_family == AF_INET6) {
        int on = 1;

        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
            perf_log_warning("setsockopt(IPV6_V6ONLY) failed");
        }
    }

    if (bind(fd, &self->local.sa.sa, self->local.length) == -1) {
        char __s[256];
        perf_log_fatal("bind: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (self->bufsize) {
        int ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
            &self->bufsize, sizeof(self->bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_RCVBUF) failed");

        ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
            &self->bufsize, sizeof(self->bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_SNDBUF) failed");
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        perf_log_fatal("fcntl(F_GETFL)");
    int ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
        perf_log_fatal("fcntl(F_SETFL)");

    self->conn_ts = perf_get_time();
    if (connect(fd, &self->server.sa.sa, self->server.length)) {
        if (errno == EINPROGRESS) {
            self->is_ready = false;
        } else {
            char __s[256];
            perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }

    return fd;
}

static ssize_t perf__tcp_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    ssize_t  n;
    uint16_t dnslen, dnslen2;

    int fd = ck_pr_load_int(&sock->fd);
    if (fd != self->recvfd) {
        /* reconnecting happened, reset buffers */
        self->have_more = false;
        self->at        = 0;
        self->recvfd    = fd;
    }

    if (!self->have_more) {
        n = recv(fd, self->recvbuf + self->at, TCP_RECV_BUF_SIZE - self->at, flags);
        if (!n) {
            return 0;
        } else if (n < 0) {
            switch (errno) {
            case ECONNREFUSED:
            case ECONNRESET:
            case ENOTCONN:
                errno = EAGAIN;
                break;
            default:
                break;
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
            self->have_more = true;
            return dnslen;
        }
    }

    self->have_more = false;
    return dnslen;
}

static ssize_t perf__tcp_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    size_t send = len < TCP_SEND_BUF_SIZE - 2 ? len : (TCP_SEND_BUF_SIZE - 2);
    // TODO: We only send what we can send, because we can't continue sending
    uint16_t dnslen = htons(send);
    ssize_t  n;

    memcpy(self->sendbuf, &dnslen, 2);
    memcpy(self->sendbuf + 2, buf, send);
    self->qid = qid;
    n         = sendto(sock->fd, self->sendbuf, send + 2, flags, dest_addr, addrlen);

    if (n < 0) {
        switch (errno) {
        case ECONNREFUSED:
        case ECONNRESET:
        case ENOTCONN:
        case EPIPE:
            self->need_reconnect = true;
            self->is_sending     = true;
            self->sending        = 0;
            errno                = EINPROGRESS;
            return -1;
        default:
            break;
        }
        return -1;
    }

    if (n < send + 2) {
        self->is_sending = true;
        self->sending    = n;
        self->flags      = flags;
        memcpy(&self->dest_addr, dest_addr, addrlen);
        self->addrlen = addrlen;
        errno         = EINPROGRESS;
        return -1;
    }

    return n - 2;
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
    if (self->need_reconnect) {
        int fd = perf__tcp_connect(sock), oldfd = ck_pr_load_int(&sock->fd);
        ck_pr_store_int(&sock->fd, fd);
        close(oldfd);
        self->need_reconnect = false;
    }

    if (self->is_ready) {
        if (self->is_sending) {
            uint16_t dnslen;
            ssize_t  n;

            memcpy(&dnslen, self->sendbuf, 2);
            dnslen = ntohs(dnslen);
            n      = sendto(sock->fd, self->sendbuf + self->sending, dnslen + 2 - self->sending, self->flags, (struct sockaddr*)&self->dest_addr, self->addrlen);
            if (n < 1) {
                switch (errno) {
                case ECONNREFUSED:
                case ECONNRESET:
                case ENOTCONN:
                case EPIPE:
                    self->need_reconnect = true;
                    if (self->sending) {
                        self->sending    = 0;
                        self->is_sending = false;
                    }
                    errno = EINPROGRESS;
                    return -1;
                default:
                    break;
                }
                return -1;
            }
            self->sending += n;
            if (self->sending < dnslen + 2) {
                errno = EINPROGRESS;
                return -1;
            }
            self->sending    = 0;
            self->is_sending = false;
            if (sock->sent) {
                sock->sent(sock, self->qid);
            }
        }
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
        if (sock->event) {
            sock->event(sock, self->conn_event, perf_get_time() - self->conn_ts);
            self->conn_event = perf_socket_event_reconnect;
        }
        if (self->is_sending) {
            errno = EINPROGRESS;
            return -1;
        }
        return 1;
    }
    default:
        break;
    }

    return -1;
}

static bool perf__tcp_have_more(struct perf_net_socket* sock)
{
    return self->have_more;
}

struct perf_net_socket* perf_net_tcp_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize)
{
    struct perf__tcp_socket* tmp  = calloc(1, sizeof(struct perf__tcp_socket)); // clang scan-build
    struct perf_net_socket*  sock = (struct perf_net_socket*)tmp;

    if (!sock) {
        perf_log_fatal("perf_net_tcp_opensocket() out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__tcp_recv;
    sock->sendto    = perf__tcp_sendto;
    sock->close     = perf__tcp_close;
    sock->sockeq    = perf__tcp_sockeq;
    sock->sockready = perf__tcp_sockready;
    sock->have_more = perf__tcp_have_more;

    self->server  = *server;
    self->local   = *local;
    self->bufsize = bufsize;
    if (self->bufsize > 0) {
        self->bufsize *= 1024;
    }
    self->conn_event = perf_socket_event_connect;

    sock->fd     = perf__tcp_connect(sock);
    self->recvfd = sock->fd;

    return sock;
}
