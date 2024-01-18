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
#include "util.h"
#include "os.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ck_pr.h>

static SSL_CTX* ssl_ctx = 0;

#define self ((struct perf__dot_socket*)sock)

struct perf__dot_socket {
    struct perf_net_socket base;

    pthread_mutex_t lock;
    SSL*            ssl;

    char   recvbuf[TCP_RECV_BUF_SIZE], sendbuf[TCP_SEND_BUF_SIZE];
    size_t at, sending;
    bool   is_ready, is_conn_ready, have_more, is_sending, do_reconnect;

    perf_sockaddr_t server, local;
    size_t          bufsize;

    uint16_t qid;

    uint64_t            conn_ts;
    perf_socket_event_t conn_event, conning_event;

    size_t       num_queries_per_conn, nqpc_timeout;
    unsigned int nqpc_sent, nqpc_recv;
    uint64_t     nqpc_ts;
};

static void perf__dot_connect(struct perf_net_socket* sock)
{
    int ret;

    self->nqpc_sent = 0;
    ck_pr_store_uint(&self->nqpc_recv, 0);
    self->nqpc_ts = 0;

    int fd = socket(self->server.sa.sa.sa_family, SOCK_STREAM, 0);
    if (fd == -1) {
        char __s[256];
        perf_log_fatal("socket: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }
    ck_pr_store_int(&sock->fd, fd);

    if (self->ssl) {
        SSL_free(self->ssl);
    }
    if (!(self->ssl = SSL_new(ssl_ctx))) {
        perf_log_fatal("SSL_new(): %s", ERR_error_string(ERR_get_error(), 0));
    }
    if (perf_net_tls_sni && !(ret = SSL_set_tlsext_host_name(self->ssl, perf_net_tls_sni))) {
        perf_log_fatal("SSL_set_tlsext_host_name(): %s", ERR_error_string(SSL_get_error(self->ssl, ret), 0));
    }
    if (!(ret = SSL_set_fd(self->ssl, sock->fd))) {
        perf_log_fatal("SSL_set_fd(): %s", ERR_error_string(SSL_get_error(self->ssl, ret), 0));
    }

    if (self->server.sa.sa.sa_family == AF_INET6) {
        int on = 1;

        if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
            perf_log_warning("setsockopt(IPV6_V6ONLY) failed");
        }
    }

    if (bind(sock->fd, &self->local.sa.sa, self->local.length) == -1) {
        char __s[256];
        perf_log_fatal("bind: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (self->bufsize > 0) {
        ret = setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF,
            &self->bufsize, sizeof(self->bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_RCVBUF) failed");

        ret = setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF,
            &self->bufsize, sizeof(self->bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_SNDBUF) failed");
    }

    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0)
        perf_log_fatal("fcntl(F_GETFL)");
    ret = fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
        perf_log_fatal("fcntl(F_SETFL)");

    self->conn_ts = perf_get_time();
    if (sock->event) {
        sock->event(sock, self->conning_event, self->conn_ts);
        self->conning_event = perf_socket_event_reconnecting;
    }
    if (connect(sock->fd, &self->server.sa.sa, self->server.length)) {
        if (errno == EINPROGRESS) {
            return;
        } else {
            char __s[256];
            perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }

    self->is_conn_ready = true;
}

static void perf__dot_reconnect(struct perf_net_socket* sock)
{
    close(sock->fd);
    self->have_more = false;
    self->at        = 0;
    if (self->sending) {
        self->sending    = 0;
        self->is_sending = false;
    }
    self->is_ready      = false;
    self->is_conn_ready = false;
    perf__dot_connect(sock);
}

static ssize_t perf__dot_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    ssize_t  n;
    uint16_t dnslen, dnslen2;

    if (!self->have_more) {
        PERF_LOCK(&self->lock);
        if (!self->is_ready) {
            PERF_UNLOCK(&self->lock);
            errno = EAGAIN;
            return -1;
        }

        n = SSL_read(self->ssl, self->recvbuf + self->at, TCP_RECV_BUF_SIZE - self->at);
        if (!n) {
            perf__dot_reconnect(sock);
            PERF_UNLOCK(&self->lock);
            errno = EAGAIN;
            return -1;
        }
        if (n < 0) {
            int err = SSL_get_error(self->ssl, n);
            switch (err) {
            case SSL_ERROR_WANT_READ:
                errno = EAGAIN;
                break;
#if OPENSSL_VERSION_NUMBER > 0x30000000L
            case SSL_ERROR_SSL:
                // OpenSSL 3.0+ returns this on EOF, treat everything as bad fd and reconnect
                errno = EBADF;
#endif
            case SSL_ERROR_SYSCALL:
                switch (errno) {
                case EBADF:
                    // treat this as a retry, can happen if sendto is reconnecting
                case ECONNREFUSED:
                case ECONNRESET:
                case ENOTCONN:
                    perf__dot_reconnect(sock);
                    errno = EAGAIN;
                    break;
                default:
                    break;
                }
                break;
            default:
                errno = EBADF;
                break;
            }
            PERF_UNLOCK(&self->lock);
            return -1;
        }
        PERF_UNLOCK(&self->lock);

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

static ssize_t perf__dot_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    size_t send = len < TCP_SEND_BUF_SIZE - 2 ? len : (TCP_SEND_BUF_SIZE - 2);
    // TODO: We only send what we can send, because we can't continue sending
    uint16_t dnslen = htons(send);
    ssize_t  n;

    PERF_LOCK(&self->lock);

    memcpy(self->sendbuf, &dnslen, 2);
    memcpy(self->sendbuf + 2, buf, send);
    self->qid = qid;

    if (!self->is_ready) {
        self->is_sending = true;
        self->sending    = 0;
        PERF_UNLOCK(&self->lock);
        errno = EINPROGRESS;
        return -1;
    }

    n = SSL_write(self->ssl, self->sendbuf, send + 2);
    if (n < 1) {
        switch (SSL_get_error(self->ssl, n)) {
        case SSL_ERROR_SYSCALL:
            switch (errno) {
            case ECONNREFUSED:
            case ECONNRESET:
            case ENOTCONN:
            case EPIPE:
                perf__dot_reconnect(sock);
                self->is_sending = true;
                self->sending    = 0;
                PERF_UNLOCK(&self->lock);
                errno = EINPROGRESS;
                return -1;
            default:
                break;
            }
            PERF_UNLOCK(&self->lock);
            return -1;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            self->is_sending = true;
            self->sending    = 0;
            PERF_UNLOCK(&self->lock);
            errno = EINPROGRESS;
            return -1;
        default:
            break;
        }
        perf_log_warning("SSL_write(): %s", ERR_error_string(SSL_get_error(self->ssl, n), 0));
        errno = EBADF;
        return -1;
    }

    if (n < send + 2) {
        self->sending    = n;
        self->is_sending = true;
        PERF_UNLOCK(&self->lock);
        errno = EINPROGRESS;
        return -1;
    }
    PERF_UNLOCK(&self->lock);

    self->nqpc_sent++;

    return n - 2;
}

static int perf__dot_close(struct perf_net_socket* sock)
{
    // TODO
    return close(sock->fd);
}

static int perf__dot_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    return sock_a->fd == sock_b->fd;
}

static int perf__dot_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    PERF_LOCK(&self->lock);
    if (self->do_reconnect) {
        perf__dot_reconnect(sock);
        self->do_reconnect = false;
    }

    if (self->is_ready) {
        if (self->is_sending) {
            uint16_t dnslen;
            ssize_t  n;

            memcpy(&dnslen, self->sendbuf, 2);
            dnslen = ntohs(dnslen);

            n = SSL_write(self->ssl, self->sendbuf + self->sending, dnslen + 2 - self->sending);
            if (n < 1) {
                switch (SSL_get_error(self->ssl, n)) {
                case SSL_ERROR_SYSCALL:
                    perf__dot_reconnect(sock);
                    PERF_UNLOCK(&self->lock);
                    return 0;
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    PERF_UNLOCK(&self->lock);
                    return 0;
                default:
                    break;
                }
                perf_log_warning("SSL_write(): %s", ERR_error_string(SSL_get_error(self->ssl, n), 0));
                PERF_UNLOCK(&self->lock);
                return 0;
            }
            PERF_UNLOCK(&self->lock);

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
        } else {
            PERF_UNLOCK(&self->lock);
        }
        if (self->num_queries_per_conn && self->nqpc_sent >= self->num_queries_per_conn) {
            if (!self->nqpc_ts) {
                self->nqpc_ts = perf_get_time() + self->nqpc_timeout;
            }
            unsigned int r = ck_pr_load_uint(&self->nqpc_recv);
            if (r >= self->nqpc_sent || perf_get_time() > self->nqpc_ts) {
                PERF_LOCK(&self->lock);
                perf__dot_reconnect(sock);
                PERF_UNLOCK(&self->lock);
            }
            return 0;
        }
        return 1;
    }

    if (!self->is_conn_ready) {
        switch (perf_os_waituntilanywritable(&sock, 1, pipe_fd, timeout)) {
        case PERF_R_TIMEDOUT:
            PERF_UNLOCK(&self->lock);
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
                    PERF_UNLOCK(&self->lock);
                    return 0;
                }
                // unrecoverable error, reconnect
                self->do_reconnect = true;
                PERF_UNLOCK(&self->lock);
                return 0;
            }
            break;
        }
        default:
            PERF_UNLOCK(&self->lock);
            return -1;
        }
        self->is_conn_ready = true;
    }

    int ret = SSL_connect(self->ssl);
    if (!ret) {
        // unrecoverable error, reconnect
        self->do_reconnect = true;
        PERF_UNLOCK(&self->lock);
        return 0;
    }
    if (ret < 0) {
        switch (SSL_get_error(self->ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            break;
        default:
            // unrecoverable error, reconnect
            self->do_reconnect = true;
        }
        PERF_UNLOCK(&self->lock);
        return 0;
    }
    self->is_ready = true;
    PERF_UNLOCK(&self->lock);
    if (sock->event) {
        sock->event(sock, self->conn_event, perf_get_time() - self->conn_ts);
        self->conn_event = perf_socket_event_reconnected;
    }
    if (self->is_sending) {
        return 0;
    }
    return 1;
}

static bool perf__dot_have_more(struct perf_net_socket* sock)
{
    return self->have_more;
}

static void perf__dot_num_queries_per_conn(struct perf_net_socket* sock, size_t num_queries_per_conn, size_t timeout)
{
    self->num_queries_per_conn = num_queries_per_conn;
    self->nqpc_timeout         = timeout;
}

struct perf_net_socket* perf_net_dot_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event)
{
    struct perf__dot_socket* tmp  = calloc(1, sizeof(struct perf__dot_socket)); // clang scan-build
    struct perf_net_socket*  sock = (struct perf_net_socket*)tmp;

    if (!sock) {
        perf_log_fatal("perf_net_dot_opensocket() out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__dot_recv;
    sock->sendto    = perf__dot_sendto;
    sock->close     = perf__dot_close;
    sock->sockeq    = perf__dot_sockeq;
    sock->sockready = perf__dot_sockready;
    sock->have_more = perf__dot_have_more;

    sock->num_queries_per_conn = perf__dot_num_queries_per_conn;

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
    PERF_MUTEX_INIT(&self->lock);

    if (!ssl_ctx) {
#ifdef HAVE_TLS_METHOD
        if (!(ssl_ctx = SSL_CTX_new(TLS_method()))) {
            perf_log_fatal("SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(), 0));
        }
        if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION)) {
            perf_log_fatal("SSL_CTX_set_min_proto_version(TLS1_2_VERSION): %s", ERR_error_string(ERR_get_error(), 0));
        }
#else
        if (!(ssl_ctx = SSL_CTX_new(SSLv23_client_method()))) {
            perf_log_fatal("SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(), 0));
        }
#endif
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    }

    perf__dot_connect(sock);

    return sock;
}
