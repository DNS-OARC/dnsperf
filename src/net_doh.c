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
#include "util.h"
#include "os.h"

#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ck_pr.h>
#include <nghttp2/nghttp2.h>

static SSL_CTX* ssl_ctx = 0;

#define self ((struct perf__doh_socket*)sock)
#define DEFAULT_MAX_CONCURRENT_STREAMS 1

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

typedef struct {
  const char *uri;
  struct http_parser_url *u;
  char *authority;
  size_t authority_len;
  char *path;
  size_t path_len;
  int32_t sid; // stream ID
} http2_stream_data;

typedef struct {
    nghttp2_session*    session;
    http2_stream_data*  stream_data;
    uint32_t max_concurrent_streams;
    uint32_t open_streams; // future use 
} perf__doh_http2_ctx_t;

struct perf__doh_socket {
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

    perf__doh_http2_ctx_t* http2; // http2 context
};

static ssize_t _perf_on_http2_send(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
    // TODO:
    return 0;
}

static ssize_t _perf_on_http2_data_provider_read(nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data)
{
    // TODO:
    return 0;
}

static int _perf_on_http2_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
    // TODO:
    return 0;
}

static int _perf_on_http2_data_recv(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
{
    // TODO:
    return 0;
}

static int _perf_on_http2_stream_close(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
{
    // TODO:
    return 0;
}

static int _perf_on_http2_frame_recv(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    // TODO:
    return 0;
}

int perf__doh_https2_init(struct perf__doh_socket* sock)
{
    assert(self);
    assert(self->ssl == NULL);
    assert(self->http2 == NULL);
    assert(self->http2->session == NULL);

    int                        ret = -1;
    nghttp2_session_callbacks* callbacks;
    nghttp2_option*            option;
  
    self->http2 = calloc(1, sizeof(perf__doh_http2_ctx_t));
    self->http2->max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;

    /* sets HTTP/2 callbacks */
    assert(nghttp2_session_callbacks_new(&callbacks) == 0);
    nghttp2_session_callbacks_set_send_callback(callbacks, _perf_on_http2_send);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, _perf_on_http2_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _perf_on_http2_data_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _perf_on_http2_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _perf_on_http2_stream_close);

    assert(nghttp2_option_new(&option) != 0);
    nghttp2_option_set_peer_max_concurrent_streams(option, self->http2->max_concurrent_streams);

    ret = nghttp2_session_client_new2(&self->http2->session, callbacks, self, option);

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);

    if (ret < 0) {
        free(self->http2);
        self->http2 = NULL;
    }

    return ret;
}

static void perf__doh_connect(struct perf_net_socket* sock)
{
    int ret;

    self->is_ready = true;

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
            self->is_ready = false;
        } else {
            char __s[256];
            perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }
}

static void perf__doh_reconnect(struct perf_net_socket* sock)
{
    close(sock->fd);
    self->have_more = false;
    self->at        = 0;
    if (self->sending) {
        self->sending    = 0;
        self->is_sending = false;
    }
    self->is_conn_ready = false;
    perf__doh_connect(sock);
}

static ssize_t perf__doh_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
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
            perf__doh_reconnect(sock);
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
            case SSL_ERROR_SYSCALL:
                switch (errno) {
                case ECONNREFUSED:
                case ECONNRESET:
                case ENOTCONN:
                    perf__doh_reconnect(sock);
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

    if (self->at > 2) {
        memcpy(&dnslen2, self->recvbuf, 2);
        dnslen2 = ntohs(dnslen2);
        if (self->at >= dnslen2 + 2) {
            self->have_more = true;
            return dnslen;
        }
    }

    // TODO: process http2 data
    // ssize_t ret = 0;
    // ret = nghttp2_session_mem_recv(self->http2->session, (uint8_t*)self->recvbuf, len);

    self->have_more = false;
    return dnslen;
}

static ssize_t perf__doh_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
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
                perf__doh_reconnect(sock);
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

    return n - 2;
}

static int perf__doh_close(struct perf_net_socket* sock)
{
    // TODO
    return close(sock->fd);
}

static int perf__doh_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    return sock_a->fd == sock_b->fd;
}

static int perf__doh_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    PERF_LOCK(&self->lock);
    if (self->do_reconnect) {
        perf__doh_reconnect(sock);
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
                    perf__doh_reconnect(sock);
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
            return 1;
        }
        PERF_UNLOCK(&self->lock);
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

static bool perf__doh_have_more(struct perf_net_socket* sock)
{
    return self->have_more;
}

struct perf_net_socket* perf_net_doh_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize)
{
    struct perf__doh_socket* tmp  = calloc(1, sizeof(struct perf__doh_socket)); // clang scan-build
    struct perf_net_socket*  sock = (struct perf_net_socket*)tmp;

    int ret = -1;

    if (!sock) {
        perf_log_fatal("perf_net_doh_opensocket() out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__doh_recv;
    sock->sendto    = perf__doh_sendto;
    sock->close     = perf__doh_close;
    sock->sockeq    = perf__doh_sockeq;
    sock->sockready = perf__doh_sockready;
    sock->have_more = perf__doh_have_more;

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
        perf_log_fatal("DNS-over-HTTPS (DoH) is supported only over TLS 1.2+");
#endif
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    #if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
    #endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
    }

    ret = perf__doh_https2_init(self);

    if (ret < 0) {
        perf_log_fatal("Unable to initialize the HTTPS2 connection");
    }
    
    perf__doh_connect(sock);

    return sock;
}