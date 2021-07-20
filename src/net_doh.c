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
/*
 * Based on HTTP/2 module in DNS shotgun by Tomáš Křížek (CZ.NIC)
 * https://gitlab.nic.cz/knot/shotgun/-/blob/master/replay/dnssim/src/output/dnssim/https2.c
 *
 * Initial PoC implementation by Atanas Argirov (PeeriX)
 * https://github.com/m0rcq
 */

#include "config.h"

#include "net.h"
#include "edns.h"
#include "parse_uri.h"
#include "log.h"
#include "strerror.h"
#include "util.h"
#include "os.h"
#include "opt.h"

#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ck_pr.h>
#include <nghttp2/nghttp2.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define DNS_GET_REQUEST_VAR "?dns="
#define DNS_MSG_MAX_SIZE 65535
#define DEFAULT_MAX_CONCURRENT_STREAMS 1

static SSL_CTX*   ssl_ctx = 0;
static struct URI doh_uri;
enum perf_doh_method {
    doh_method_get,
    doh_method_post
};
static enum perf_doh_method doh_method = doh_method_get;

#define self ((struct perf__doh_socket*)sock)

#define MAKE_NV(NAME, VALUE)                                                  \
    {                                                                         \
        (uint8_t*)NAME, (uint8_t*)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
            NGHTTP2_NV_FLAG_NONE                                              \
    }

#define MAKE_NV_CS(NAME, VALUE)                                           \
    {                                                                     \
        (uint8_t*)NAME, (uint8_t*)VALUE, sizeof(NAME) - 1, strlen(VALUE), \
            NGHTTP2_NV_FLAG_NONE                                          \
    }

#define MAKE_NV_LEN(NAME, VALUE, VALUELEN)                           \
    {                                                                \
        (uint8_t*)NAME, (uint8_t*)VALUE, sizeof(NAME) - 1, VALUELEN, \
            NGHTTP2_NV_FLAG_NONE                                     \
    }

typedef struct {
    uint8_t *buf, *bufp;
    size_t   len, buf_len;
} http2_data_provider_t;

typedef struct {
    const char* uri;
    char*       authority;
    char*       path;
    int32_t     stream_id;
} http2_stream_t;

typedef struct {
    nghttp2_session*      session;
    http2_stream_t        stream;
    http2_data_provider_t payload;
    uint32_t              max_concurrent_streams;
    bool                  settings_sent;
    char                  dnsmsg[DNS_MSG_MAX_SIZE];
    size_t                dnsmsg_at;
    bool                  dnsmsg_completed;
} http2_session_t;

struct perf__doh_socket {
    struct perf_net_socket base;

    pthread_mutex_t lock;
    SSL*            ssl;

    char recvbuf[TCP_RECV_BUF_SIZE];
    char sendbuf[TCP_SEND_BUF_SIZE];
    bool is_ready, is_conn_ready, is_ssl_ready, is_sending, is_post_sending;
    // bool have_more; TODO
    bool do_reconnect;

    perf_sockaddr_t server, local;
    size_t          bufsize;

    uint16_t qid;

    uint64_t            conn_ts;
    perf_socket_event_t conn_event, conning_event;

    http2_session_t http2; // http2 session data
};

static nghttp2_session_callbacks* _nghttp2_callbacks = 0;
static nghttp2_option*            _nghttp2_option    = 0;

void perf_net_doh_parse_uri(const char* uri)
{
    if (parse_uri(&doh_uri, uri)) {
        perf_log_warning("invalid DNS-over-HTTPS URI");
        perf_opt_usage();
        exit(1);
    }
}

void perf_net_doh_parse_method(const char* method)
{
    if (!strcmp(method, "GET")) {
        doh_method = doh_method_get;
        return;
    } else if (!strcmp(method, "POST")) {
        doh_method = doh_method_post;
        return;
    }

    perf_log_warning("invalid DNS-over-HTTPS method");
    perf_opt_usage();
    exit(1);
}

static void perf__doh_connect(struct perf_net_socket* sock)
{
    int ret;

    // TODO: remove all of this stream, uri is static data
    free(self->http2.stream.path);
    if (!(self->http2.stream.path = calloc(1, doh_uri.pathlen + 1))) {
        perf_log_fatal("out of memory");
    }
    memcpy(self->http2.stream.path, doh_uri.path, doh_uri.pathlen);

    free(self->http2.stream.authority);
    self->http2.stream.authority = calloc(1, doh_uri.hostportlen + 1);
    if (!self->http2.stream.authority) {
        perf_log_fatal("out of memory");
    }
    memcpy(self->http2.stream.authority, doh_uri.hostport, doh_uri.hostportlen);

    nghttp2_session_del(self->http2.session);
    ret = nghttp2_session_client_new2(&self->http2.session, _nghttp2_callbacks, self, _nghttp2_option);
    if (ret < 0) {
        perf_log_fatal("Failed to initialize http2 session: %s", nghttp2_strerror(ret));
    }

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
            return;
        } else {
            char __s[256];
            perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
    }

    self->is_conn_ready = true;
}

static void perf__doh_reconnect(struct perf_net_socket* sock)
{
    close(sock->fd);
    // self->have_more = false; TODO

    self->http2.settings_sent = false;
    self->is_ready            = false;
    self->is_conn_ready       = false;
    self->is_ssl_ready        = false;

    self->http2.dnsmsg_at        = 0;
    self->http2.dnsmsg_completed = false;

    perf__doh_connect(sock);
}

static ssize_t perf__doh_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    ssize_t n   = 0;
    ssize_t ret = 0;

    // read TLS data here instead of nghttp2_recv_callback
    PERF_LOCK(&self->lock);
    if (!self->is_ready) {
        PERF_UNLOCK(&self->lock);
        errno = EAGAIN;
        return -1;
    }

    n = SSL_read(self->ssl, self->recvbuf, TCP_RECV_BUF_SIZE);
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

    // this will be processed by nghttp2 callbacks
    // self->recvbuf holds the payload
    ret = nghttp2_session_mem_recv(self->http2.session,
        (uint8_t*)self->recvbuf,
        n);
    if (ret < 0) {
        perf_log_warning("nghttp2_session_mem_recv failed: %s",
            nghttp2_strerror((int)ret));
        PERF_UNLOCK(&self->lock);
        return -1;
    }
    // TODO: handle partial mem_recv
    if (ret != n) {
        perf_log_fatal("perf__doh_recv() mem_recv did not take all");
    }

    // need to execute nghttp2_session_send if the receive ops triggered data frames
    ret = nghttp2_session_send(self->http2.session);
    if (ret < 0) {
        // TODO: reconnect?
        perf_log_warning("nghttp2_session_send failed: %s", nghttp2_strerror((int)ret));
        PERF_UNLOCK(&self->lock);
        return -1;
    }

    if (self->http2.dnsmsg_completed) {
        if (self->http2.dnsmsg_at <= len) {
            len = self->http2.dnsmsg_at;
        }
        memcpy(buf, self->http2.dnsmsg, len);
        self->http2.dnsmsg_completed = false;
        self->http2.dnsmsg_at        = 0;

        // self->have_more = false; TODO
        PERF_UNLOCK(&self->lock);
        return len;
    } else {
        // self->have_more = true; TODO
        PERF_UNLOCK(&self->lock);
        errno = EAGAIN;
        return -1;
    }
}

static void _submit_dns_query_get(struct perf_net_socket* sock, const void* buf, size_t len)
{
    int32_t stream_id;

    const size_t path_len = strlen(self->http2.stream.path)
                            + sizeof(DNS_GET_REQUEST_VAR) - 1
                            + (4 * ((len + 2) / 3)) + 1;
    char  full_path[path_len];
    char* p = &full_path[0];

    memcpy(p, self->http2.stream.path, strlen(self->http2.stream.path));
    p += strlen(self->http2.stream.path);

    memcpy(p, DNS_GET_REQUEST_VAR, sizeof(DNS_GET_REQUEST_VAR) - 1);
    p += sizeof(DNS_GET_REQUEST_VAR) - 1;

    EVP_EncodeBlock((unsigned char*)p, buf, len);
    // RFC8484 requires base64url (RFC4648)
    // and Padding characters (=) for base64url MUST NOT be included.
    // base64url alphabet is the same as base64 except + is - and / is _
    while (*p) {
        switch (*p) {
        case '+':
            *p++ = '-';
            break;
        case '/':
            *p++ = '_';
            break;
        case '=':
            *p = 0;
            break;
        default:
            p++;
        }
    }

    const nghttp2_nv hdrs[] = {
        MAKE_NV(":method", "GET"),
        MAKE_NV(":scheme", "https"),
        MAKE_NV_CS(":authority", self->http2.stream.authority),
        MAKE_NV_LEN(":path", full_path, p - full_path),
        MAKE_NV("accept", "application/dns-message"),
        MAKE_NV("user-agent", "nghttp2-dnsperf/" NGHTTP2_VERSION)
    };

    stream_id = nghttp2_submit_request(self->http2.session,
        NULL,
        hdrs,
        sizeof(hdrs) / sizeof(hdrs[0]),
        NULL,
        &self->http2.stream);
    if (stream_id < 0) {
        perf_log_fatal("Failed to submit HTTP2 request: %s", nghttp2_strerror(stream_id));
    }

    self->http2.stream.stream_id = stream_id;
}

static ssize_t _payload_read_cb(nghttp2_session* session,
    int32_t stream_id, uint8_t* buf,
    size_t length, uint32_t* data_flags,
    nghttp2_data_source* source,
    void*                sock)
{
    http2_data_provider_t* payload = source->ptr;

    ssize_t payload_size = length < payload->len ? length : payload->len;

    memcpy(buf, payload->bufp, payload_size);
    payload->bufp += payload_size;
    payload->len -= payload_size;
    // check for EOF
    if (payload->len == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        self->is_post_sending = false;
    }

    return payload_size;
}

static void _submit_dns_query_post(struct perf_net_socket* sock, const void* buf, size_t len)
{
    int32_t stream_id;

    // POST requires DATA flow-controlled payload that local endpoint
    // can send across without issuing WINDOW_UPDATE
    // we need to check for this and bounce back the request if the
    // payload > remote window size
    // TODO: are these needed? can they be checked on connect?
    int remote_window_size = nghttp2_session_get_remote_window_size(self->http2.session);
    if (remote_window_size < 0) {
        perf_log_fatal("failed to get http2 session remote window size");
    }
    if (len > remote_window_size) {
        perf_log_fatal("remote window size is too small for POST payload");
    }

    // compose content-length
    char payload_size[20];
    int  payload_size_len = snprintf(payload_size, sizeof(payload_size), "%ld", len);
    // TODO: check snprintf()

    const nghttp2_nv hdrs[] = {
        MAKE_NV(":method", "POST"),
        MAKE_NV(":scheme", "https"),
        MAKE_NV_CS(":authority", self->http2.stream.authority),
        MAKE_NV_CS(":path", self->http2.stream.path),
        MAKE_NV("accept", "application/dns-message"),
        MAKE_NV("content-type", "application/dns-message"),
        MAKE_NV_LEN("content-length", payload_size, payload_size_len),
        MAKE_NV("user-agent", "nghttp2-dnsperf/" NGHTTP2_VERSION)
    };

    if (len > self->http2.payload.buf_len) {
        self->http2.payload.buf_len = ((len / MAX_EDNS_PACKET) + 1) * MAX_EDNS_PACKET;
        if (!(self->http2.payload.buf = realloc(self->http2.payload.buf, self->http2.payload.buf_len))) {
            perf_log_fatal("perf_net_doh: out of memory");
        }
    }
    memcpy(self->http2.payload.buf, buf, len);
    self->http2.payload.bufp = self->http2.payload.buf;
    self->http2.payload.len  = len;
    self->is_post_sending    = true;

    // we need data provider to pass to submit()

    nghttp2_data_provider data_provider = {
        .source.ptr    = &self->http2.payload,
        .read_callback = _payload_read_cb
    };
    stream_id = nghttp2_submit_request(self->http2.session,
        NULL,
        hdrs,
        sizeof(hdrs) / sizeof(hdrs[0]),
        &data_provider,
        sock);
    if (stream_id < 0) {
        perf_log_fatal("Failed to submit HTTP2 request: %s", nghttp2_strerror(stream_id));
    }

    self->http2.stream.stream_id = stream_id;
}

static ssize_t perf__doh_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    PERF_LOCK(&self->lock);

    if (!self->is_ready) {
        // TODO: query will be lost here
        PERF_UNLOCK(&self->lock);
        errno = EINPROGRESS;
        return -1;
    }

    if (self->is_sending) {
        perf_log_fatal("called when sending");
    }

    self->qid = qid;

    switch (doh_method) {
    case doh_method_get:
        _submit_dns_query_get(sock, buf, len);
        break;
    case doh_method_post:
        _submit_dns_query_post(sock, buf, len);
        break;
    }

    int ret = nghttp2_session_send(self->http2.session);
    if (ret < 0) {
        perf_log_warning("nghttp2_session_send failed: %s", nghttp2_strerror(ret));
        // TODO: return inprog? other err?
    }

    if (nghttp2_session_want_write(self->http2.session) || self->is_post_sending) {
        self->is_sending = true;
        PERF_UNLOCK(&self->lock);
        errno = EINPROGRESS;
        return -1;
    }
    PERF_UNLOCK(&self->lock);

    return ret ? ret : len;
}

static int perf__doh_close(struct perf_net_socket* sock)
{
    // TODO
    // ?????:
    // if (self->http2) {
    //     http2_session_free(sock);
    // }
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
        // do nghttp2 I/O send to flush outstanding frames
        int ret = nghttp2_session_send(self->http2.session);
        if (ret != 0) {
            perf_log_warning("nghttp2_session_send failed: %s", nghttp2_strerror(ret));
            self->do_reconnect = true;
            PERF_UNLOCK(&self->lock);
            return 0;
        }

        bool sent = false;
        if (self->is_sending) {
            if (nghttp2_session_want_write(self->http2.session) || self->is_post_sending) {
                PERF_UNLOCK(&self->lock);
                return 0;
            }
            self->is_sending = false;
            sent             = true;
        }
        PERF_UNLOCK(&self->lock);
        if (sent && sock->sent) {
            sock->sent(sock, self->qid);
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

    if (!self->is_ssl_ready) {
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

        const uint8_t* alpn     = NULL;
        uint32_t       alpn_len = 0;
#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_get0_next_proto_negotiated(self->ssl, &alpn, &alpn_len);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (alpn == NULL) {
            SSL_get0_alpn_selected(self->ssl, &alpn, &alpn_len);
        }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

        if (alpn == NULL || alpn_len != 2 || memcmp("h2", alpn, 2) != 0) {
            self->do_reconnect = true;
            PERF_UNLOCK(&self->lock);
            return 0;
        }
        self->is_ssl_ready = true;
    }

    if (!self->http2.settings_sent) {
        // send settings
        // TODO: does sending settings need session_send()?
        nghttp2_settings_entry iv[] = {
            { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_CONCURRENT_STREAMS },
            { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
            { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535 }
        };
        int ret = nghttp2_submit_settings(self->http2.session, NGHTTP2_FLAG_NONE, iv,
            sizeof(iv) / sizeof(*iv));
        if (ret != 0) {
            perf_log_warning("Could not submit https2 SETTINGS: %s", nghttp2_strerror(ret));
            self->do_reconnect = true;
            PERF_UNLOCK(&self->lock);
            return 0;
        }
        self->http2.settings_sent = true;
    }

    self->is_ready = true;
    PERF_UNLOCK(&self->lock);

    if (sock->event) {
        sock->event(sock, self->conn_event, perf_get_time() - self->conn_ts);
        self->conn_event = perf_socket_event_reconnected;
    }

    return 1;
}

static bool perf__doh_have_more(struct perf_net_socket* sock)
{
    // return self->have_more; TODO
    return false;
}

/* nghttp2 callbacks */

static ssize_t _http2_send_cb(nghttp2_session* session,
    const uint8_t*                             data,
    size_t                                     length,
    int                                        flags,
    void*                                      sock)
{
    ssize_t n;
    (void)session;
    (void)flags;

    // TODO: remove once non-experimental
    if (!PERF_TRYLOCK(&self->lock)) {
        perf_log_fatal("_http2_send_cb called without lock");
    }

    if (!self->is_ready) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    // TODO: verify partial write
    n = SSL_write(self->ssl, data, length);
    if (n < 1) {
        switch (SSL_get_error(self->ssl, n)) {
        case SSL_ERROR_SYSCALL:
            switch (errno) {
            case ECONNREFUSED:
            case ECONNRESET:
            case ENOTCONN:
            case EPIPE:
                perf__doh_reconnect(sock);
                errno = EINPROGRESS;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            default:
                break;
            }
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            errno = EINPROGRESS;
            return NGHTTP2_ERR_WOULDBLOCK;
        default:
            break;
        }
        perf_log_warning("SSL_write(): %s", ERR_error_string(SSL_get_error(self->ssl, n), 0));
        errno = EBADF;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return n;
}

static int _http2_frame_recv_cb(nghttp2_session* session, const nghttp2_frame* frame, void* sock)
{
    // TODO: remove once non-experimental
    if (!PERF_TRYLOCK(&self->lock)) {
        perf_log_fatal("_http2_frame_recv_cb called without lock");
    }

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        break;
    case NGHTTP2_DATA:
        // we are interested in DATA frame which will carry the DNS response
        // NGHTTP2_FLAG_END_STREAM indicates that we have the data in full
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            // TODO: what's the point of below code? if dnsmsg_at > max size then it will already done a buffer overflow
            // if (self->http2.dnsmsg_at > DNS_MSG_MAX_SIZE) {
            //     perf_log_warning("DNS response > DNS message maximum size");
            //     return NGHTTP2_ERR_CALLBACK_FAILURE;
            // }

            if (self->http2.dnsmsg_completed) {
                perf_log_fatal("_http2_frame_recv_cb: frame received when already having a dns msg");
            }

            self->http2.dnsmsg_completed = true;
            // self->have_more               = false; TODO
        }
        break;
    case NGHTTP2_SETTINGS:
        break;
    case NGHTTP2_RST_STREAM:
        break;
    case NGHTTP2_GOAWAY:
        break;
    }

    return 0;
}

static int _http2_data_chunk_recv_cb(nghttp2_session* session,
    uint8_t                                           flags,
    int32_t                                           stream_id,
    const uint8_t*                                    data,
    size_t len, void* sock)
{
    (void)flags;

    // TODO: remove once non-experimental
    if (!PERF_TRYLOCK(&self->lock)) {
        perf_log_fatal("_http2_data_chunk_recv_cb called without lock");
    }

    if (self->http2.dnsmsg_completed) {
        perf_log_fatal("_http2_data_chunk_recv_cb: chunk received when already having a dns msg");
    }

    // TODO: point of nghttp2_session_get_stream_user_data() code?
    // if (nghttp2_session_get_stream_user_data(session, stream_id)) {
    if (self->http2.dnsmsg_at + len > DNS_MSG_MAX_SIZE) {
        perf_log_warning("http2 chunk data exceeds DNS message max size");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    memcpy(self->http2.dnsmsg + self->http2.dnsmsg_at, data, len);
    self->http2.dnsmsg_at += len;
    // }

    return 0;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/* NPN TLS extension check */
static int select_next_proto_cb(SSL* ssl, unsigned char** out,
    unsigned char* outlen, const unsigned char* in,
    unsigned int inlen, void* arg)
{
    (void)ssl;
    (void)arg;

    if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
        perf_log_warning("Server did not advertise %u", NGHTTP2_PROTO_VERSION_ID);
        return SSL_TLSEXT_ERR_ALERT_WARNING;
    }

    return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

struct perf_net_socket* perf_net_doh_opensocket(const perf_sockaddr_t* server, const perf_sockaddr_t* local, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event)
{
    struct perf__doh_socket* tmp  = calloc(1, sizeof(struct perf__doh_socket)); // clang scan-build
    struct perf_net_socket*  sock = (struct perf_net_socket*)tmp;

    if (!sock) {
        perf_log_fatal("perf_net_doh_opensocket(): out of memory");
        return 0; // needed for clang scan build
    }

    sock->recv      = perf__doh_recv;
    sock->sendto    = perf__doh_sendto;
    sock->close     = perf__doh_close;
    sock->sockeq    = perf__doh_sockeq;
    sock->sockready = perf__doh_sockready;
    sock->have_more = perf__doh_have_more;

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

    if (!(self->http2.payload.buf = malloc(MAX_EDNS_PACKET))) {
        perf_log_fatal("perf_net_doh_opensocket(): out of memory");
    }
    self->http2.payload.buf_len = MAX_EDNS_PACKET;

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
#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char*)"\x02h2", 3);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
    }

    /* setup HTTP/2 callbacks */
    if (!_nghttp2_callbacks) {
        if (nghttp2_session_callbacks_new(&_nghttp2_callbacks)) {
            perf_log_fatal("Unable to create nghttp2 callbacks: out of memory");
        }
        nghttp2_session_callbacks_set_send_callback(_nghttp2_callbacks, _http2_send_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(_nghttp2_callbacks, _http2_data_chunk_recv_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(_nghttp2_callbacks, _http2_frame_recv_cb);
    }

    /* setup HTTP/2 options */
    if (!_nghttp2_option) {
        if (nghttp2_option_new(&_nghttp2_option)) {
            perf_log_fatal("Unable to create nghttp2 options: out of memory");
        }
        nghttp2_option_set_peer_max_concurrent_streams(_nghttp2_option, DEFAULT_MAX_CONCURRENT_STREAMS);
    }

    perf__doh_connect(sock);

    return sock;
}
