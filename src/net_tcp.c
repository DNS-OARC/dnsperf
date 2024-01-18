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

/*

About state sync between sending and receiving thread

Two variables in the TCP socket struct are used with libck to atomically
sync states between thread w.r.t connect/reconnect events.

  sock->fd is controlled by the sending thread (ST)
  self->recv_need_reconn is controlled by receiving thread (RT)

On connect/reconnect ST will open a new socket and atomically store it
into sock->fd.

When RT is trying to receive it will atomically load sock->fd and store it
in self->recvfd. Before storing it, it will compare it to what already in
self->recvfd and if it differ then a connect/reconnect event happend and RT
will reset receiving state and buffers.

If RT detects a disconnection it will atomically store self->recvfd into
self->recv_need_reconn to signal to ST that it needs to reconnect.

ST will load and check self->recv_need_reconn before sending and when
checking socket readiness, if its the same as sock->fd then it will start
reconnecting.

*/

struct perf__tcp_socket {
    struct perf_net_socket base;

    char   recvbuf[TCP_RECV_BUF_SIZE], sendbuf[TCP_SEND_BUF_SIZE];
    size_t at, sending;
    bool   is_ready, need_reconnect, have_more, is_sending;

    perf_sockaddr_t server, local;
    size_t          bufsize;

    int recvfd;
    int recv_need_reconn;

    uint16_t qid;

    uint64_t            conn_ts;
    perf_socket_event_t conn_event, conning_event;

    size_t       num_queries_per_conn, nqpc_timeout;
    unsigned int nqpc_sent, nqpc_recv;
    uint64_t     nqpc_ts;
};

static int perf__tcp_connect(struct perf_net_socket* sock)
{
    int fd;

    self->is_ready  = true;
    self->nqpc_sent = 0;
    ck_pr_store_uint(&self->nqpc_recv, 0);
    self->nqpc_ts = 0;

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
    if (sock->event) {
        sock->event(sock, self->conning_event, self->conn_ts);
        self->conning_event = perf_socket_event_reconnecting;
    }
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
            // need reconnect
            ck_pr_store_int(&self->recv_need_reconn, fd);
            return 0;
        } else if (n < 0) {
            switch (errno) {
            case EBADF:
                // treat this as a retry, can happen if sendto is reconnecting
            case ECONNREFUSED:
            case ECONNRESET:
            case ENOTCONN:
                // need reconnect
                ck_pr_store_int(&self->recv_need_reconn, fd);
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
    if (self->num_queries_per_conn) {
        ck_pr_inc_uint(&self->nqpc_recv);
    }

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

    int recv_need_reconn = ck_pr_load_int(&self->recv_need_reconn);
    if (recv_need_reconn == sock->fd) {
        self->need_reconnect = true;
        self->is_sending     = true;
        self->sending        = 0;
        errno                = EINPROGRESS;
        return -1;
    }

    n = sendto(sock->fd, self->sendbuf, send + 2, 0, 0, 0);

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
        errno            = EINPROGRESS;
        return -1;
    }
    self->nqpc_sent++;

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
    int recv_need_reconn = ck_pr_load_int(&self->recv_need_reconn);
    if (recv_need_reconn == sock->fd || self->need_reconnect) {
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
            n      = sendto(sock->fd, self->sendbuf + self->sending, dnslen + 2 - self->sending, 0, 0, 0);
            if (n < 0) {
                if (errno == EAGAIN) {
                    return 0;
                }
                int fd = perf__tcp_connect(sock), oldfd = ck_pr_load_int(&sock->fd);
                ck_pr_store_int(&sock->fd, fd);
                close(oldfd);
                if (self->sending) {
                    self->sending    = 0;
                    self->is_sending = false;
                }
                goto conn_cont;
            }
            self->sending += n;
            if (self->sending < dnslen + 2) {
                return 0;
            }
            self->sending    = 0;
            self->is_sending = false;
            if (sock->sent) {
                sock->sent(sock, self->qid);
            }
            self->nqpc_sent++;
        }
        if (self->num_queries_per_conn && self->nqpc_sent >= self->num_queries_per_conn) {
            if (!self->nqpc_ts) {
                self->nqpc_ts = perf_get_time() + self->nqpc_timeout;
            }
            unsigned int r = ck_pr_load_uint(&self->nqpc_recv);
            if (r >= self->nqpc_sent || perf_get_time() > self->nqpc_ts) {
                self->need_reconnect = true;
            }
            return 0;
        }
        return 1;
    }

conn_cont:
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
            // unrecoverable error, reconnect
            self->need_reconnect = true;
            return 0;
        }
        self->is_ready = true;
        if (sock->event) {
            sock->event(sock, self->conn_event, perf_get_time() - self->conn_ts);
            self->conn_event = perf_socket_event_reconnected;
        }
        if (self->is_sending) {
            uint16_t dnslen;
            ssize_t  n;

            memcpy(&dnslen, self->sendbuf, 2);
            dnslen = ntohs(dnslen);
            n      = sendto(sock->fd, self->sendbuf + self->sending, dnslen + 2 - self->sending, 0, 0, 0);
            if (n < 0) {
                if (errno != EAGAIN) {
                    self->need_reconnect = true;
                }
                return 0;
            }
            self->sending += n;
            if (self->sending < dnslen + 2) {
                return 0;
            }
            self->sending    = 0;
            self->is_sending = false;
            if (sock->sent) {
                sock->sent(sock, self->qid);
            }
            self->nqpc_sent++;
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

static void perf__tcp_num_queries_per_conn(struct perf_net_socket* sock, size_t num_queries_per_conn, size_t timeout)
{
    self->num_queries_per_conn = num_queries_per_conn;
    self->nqpc_timeout         = timeout;
}

struct perf_net_socket* perf_net_tcp_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event)
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

    sock->num_queries_per_conn = perf__tcp_num_queries_per_conn;

    sock->data  = data;
    sock->sent  = sent;
    sock->event = event;

    self->server  = *server;
    self->local   = *local;
    self->bufsize = bufsize;
    if (self->bufsize > 0) {
        self->bufsize *= 1024;
    }
    self->conning_event = perf_socket_event_connecting;
    self->conn_event    = perf_socket_event_connected;

    sock->fd               = perf__tcp_connect(sock);
    self->recvfd           = sock->fd;
    self->recv_need_reconn = -1;

    return sock;
}
