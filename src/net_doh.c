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
#include <openssl/bio.h>
#include <openssl/evp.h>

static SSL_CTX* ssl_ctx = 0;
char net_doh_uri[DOH_TEMPLATE_URI_MAX_SIZE];
char net_doh_method[DOH_METHOD_MAX_SIZE];

#define self ((struct perf__doh_socket*)sock)
#define DEFAULT_MAX_CONCURRENT_STREAMS 100

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_LEN(NAME, VALUE, VALUELEN)                                     \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define DNS_GET_REQUEST_VAR "dns="
#define DNS_MSG_MAX_SIZE 65535 // TODO: review TCP bufsize is only 16 x 1024

#define debugx(format, args...) fprintf(stderr, "> " format "\n", ##args)

typedef struct {
  const char *uri;
  char *authority;
  char *path;
  int32_t stream_id; // stream ID
} http2_stream_t;

typedef struct {
    nghttp2_session* session;
    http2_stream_t* stream;
    uint32_t max_concurrent_streams;
    bool settings_sent;
    char dnsmsg[DNS_MSG_MAX_SIZE];
    size_t dnsmsg_at;
    bool dnsmsg_completed;
} http2_session_t;

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

    http2_session_t* http2; // http2 session data
};

typedef struct perf__doh_socket perf__doh_socket_t;

// TODO: re-implement or use this - TBD. Out of scope for the project
// From: https://github.com/nghttp2/nghttp2/blob/master/examples/client.c
// Copyright (c) 2013 Tatsuhiro Tsujikawa
// --- vvv ---
struct URI {
  const char *host;
  /* In this program, path contains query component as well. */
  const char *path;
  size_t pathlen;
  const char *hostport;
  size_t hostlen;
  size_t hostportlen;
  uint16_t port;
};

static int parse_uri(struct URI *res, char *uri) {
  /* We only interested in https */
  size_t len, i, offset;
  int ipv6addr = 0;
  memset(res, 0, sizeof(struct URI));
  len = strlen(uri);
  if (len < 9 || memcmp("https://", uri, 8) != 0) {
    return -1;
  }
  offset = 8;
  res->host = res->hostport = &uri[offset];
  res->hostlen = 0;
  if (uri[offset] == '[') {
    /* IPv6 literal address */
    ++offset;
    ++res->host;
    ipv6addr = 1;
    for (i = offset; i < len; ++i) {
      if (uri[i] == ']') {
        res->hostlen = i - offset;
        offset = i + 1;
        break;
      }
    }
  } else {
    const char delims[] = ":/?#";
    for (i = offset; i < len; ++i) {
      if (strchr(delims, uri[i]) != NULL) {
        break;
      }
    }
    res->hostlen = i - offset;
    offset = i;
  }
  if (res->hostlen == 0) {
    return -1;
  }
  /* Assuming https */
  res->port = 443;
  if (offset < len) {
    if (uri[offset] == ':') {
      /* port */
      const char delims[] = "/?#";
      int port = 0;
      ++offset;
      for (i = offset; i < len; ++i) {
        if (strchr(delims, uri[i]) != NULL) {
          break;
        }
        if ('0' <= uri[i] && uri[i] <= '9') {
          port *= 10;
          port += uri[i] - '0';
          if (port > 65535) {
            return -1;
          }
        } else {
          return -1;
        }
      }
      if (port == 0) {
        return -1;
      }
      offset = i;
      res->port = (uint16_t)port;
    }
  }
  res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
  for (i = offset; i < len; ++i) {
    if (uri[i] == '#') {
      break;
    }
  }
  if (i - offset == 0) {
    res->path = "/";
    res->pathlen = 1;
  } else {
    res->path = &uri[offset];
    res->pathlen = i - offset;
  }
  return 0;
}
// --- ^^^ ----

// use base64_{encode/decode} based on OpenSSL's EVP

int base64_encode(const uint8_t *in, 
                  const uint8_t len,
                  uint8_t *out) 
{
    int ret = EVP_EncodeBlock((unsigned char *) out, in, len);
    return ret;
}

int base64_decode(const uint8_t *in, 
                  const uint8_t len,
                  uint8_t *out) 
{
    int ret = EVP_DecodeBlock((unsigned char *) out, in, len);
    return ret;
}

// TODO: move
static void perf__doh_connect(struct perf_net_socket* sock)
{
    int ret;

    debugx("doh_connect - qid: %d", self->qid);
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

static int _submit_dns_query_get(struct perf_net_socket* sock, const void* buf, size_t len)
{
    int32_t stream_id;
    char *cp;
    int ret = -1;
   
    // GET -> convert to base64
    uint32_t out_len = 4 * ((len + 2) / 3);
    uint8_t* base64_dns_msg = calloc(1, out_len + 1);

    if (!base64_dns_msg) {
        perf_log_fatal("failed to allocate memory");
    }

    ret = base64_encode(buf, len, base64_dns_msg);
    if (ret < 0) {
        free(base64_dns_msg);
        perf_log_fatal("base64_encode() failed");
    }

    base64_dns_msg[ret] = '\0';

    // RFC8484 requires base64url (RFC4648)
    // and Padding characters (=) for base64url MUST NOT be included.
    // base64url alphabet is the same as base64 except + is - and / is _
    cp = base64_dns_msg + ret - 2;
    if (*cp == '=') {
        *cp = '\0';
        ret -= 2;
    } else if (*++cp == '=') {
        *cp = '\0';
        ret --;
    }
    
    cp = base64_dns_msg;
    while (*cp) {
        if (*cp == '+') {
            *cp = '-';
        } else if (*cp == '/') {
            *cp = '_';
        }
        cp ++;
    }

    const size_t path_len = strlen(self->http2->stream->path) + 
                            sizeof(DNS_GET_REQUEST_VAR) - 1 +
                            ret;

    char full_path[path_len];
    memcpy(full_path, self->http2->stream->path, strlen(self->http2->stream->path));
    memcpy(&full_path[strlen(self->http2->stream->path)], 
           DNS_GET_REQUEST_VAR,  
           sizeof(DNS_GET_REQUEST_VAR) - 1);
    memcpy(&full_path[strlen(self->http2->stream->path) + sizeof(DNS_GET_REQUEST_VAR) - 1],
           base64_dns_msg,
           ret
           );

    free(base64_dns_msg);

    const nghttp2_nv hdrs[] = {
                                MAKE_NV(":method", "GET"),
                                MAKE_NV(":scheme", "https"),
                                MAKE_NV_CS(":authority", self->http2->stream->authority),
                                MAKE_NV_LEN(":path", full_path, strlen(self->http2->stream->path) + sizeof(DNS_GET_REQUEST_VAR) - 1 + ret),
                                MAKE_NV("accept", "application/dns-message"),
                                MAKE_NV("user-agent", "nghttp2-dnsperf/" NGHTTP2_VERSION)};
    
    for (size_t i = 0; i < sizeof(hdrs) / sizeof(hdrs[0]); ++i) {
        fwrite(hdrs[i].name, 1, hdrs[i].namelen, stderr);
        fprintf(stderr, ": |");
        fwrite(hdrs[i].value, 1, hdrs[i].valuelen, stderr);
        fprintf(stderr, "|");
        fprintf(stderr, "\n");
    }
    
    stream_id = nghttp2_submit_request(self->http2->session,
                                        NULL,
                                        hdrs,
                                        sizeof(hdrs) / sizeof(hdrs[0]),
                                        NULL,
                                        self->http2->stream);
    if (stream_id < 0) {
        perf_log_fatal("Failed to submit HTTP2 request: %s", nghttp2_strerror(stream_id));
    }

    self->http2->stream->stream_id = stream_id;

    debugx("qid: %d, stream_id: %d", self->qid, stream_id);

    ret = nghttp2_session_send(self->http2->session);
    if (ret < 0) {
        perf_log_warning("nghttp2_session_send failed: %d", ret);
        return -1;
    }

    return 0;
}

static int _submit_dns_query_post(struct perf_net_socket* sock, const void* buf, size_t len)
{
    return 0;
}

static http2_stream_t* http2_stream_init(struct URI* uri)
{
    http2_stream_t *stream_data = calloc(1, sizeof(http2_stream_t));

    stream_data->path = calloc(1, uri->pathlen + 1);
    memcpy(stream_data->path, uri->path, uri->pathlen);
    stream_data->path[uri->pathlen] = '\0';

    stream_data->authority = calloc(1, uri->hostportlen + 1);
    memcpy(stream_data->authority, uri->hostport, uri->hostportlen);
    stream_data->authority[uri->hostportlen] = '\0';

    return stream_data;
}

static void http2_stream_free(http2_stream_t *stream_data) {
    free(stream_data->path);
    free(stream_data->authority);
    free(stream_data);
}

http2_session_t* http2_session_init()
{
    http2_session_t *session_data = calloc(1, sizeof(http2_session_t));
    memset(session_data, 0, sizeof(http2_session_t));
    return session_data;
}

static void http2_session_free(struct perf_net_socket* sock) 
{
    if (self->ssl) {
        SSL_shutdown(self->ssl);
    }
    
    nghttp2_session_del(self->http2->session);
    self->http2->session = NULL;

    if (self->http2->stream) {
        http2_stream_free(self->http2->stream);
        self->http2->stream = NULL;
    }

    free(self->http2);
    self->http2 = NULL;
}

/* nghttp2 callbacks */

// TODO: remove - we handle TLS read upstream
static ssize_t _http2_recv_cb(nghttp2_session* session,
                          const uint8_t* data, 
                          size_t len, 
                          int flags,
                          void* user_data)
{
    // TODO:
    debugx("http2_recv_cb - len: %d", len);
    return 0;
}

static ssize_t _http2_send_cb(nghttp2_session* session, 
                                    const uint8_t* data, 
                                    size_t length, 
                                    int flags, 
                                    void* user_data)
{
    ssize_t n;
    (void)session;
    (void)flags;

    struct perf_net_socket *sock = (struct perf_net_socket *)user_data;
    (void)session;
    (void)flags;

    if (!self->is_ready) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

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
                self->is_sending = true;
                self->sending    = 0;
                errno = EINPROGRESS;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            default:
                break;
            }
            PERF_UNLOCK(&self->lock);
            return -1;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            self->is_sending = true;
            self->sending    = 0;
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

static ssize_t _http2_data_provider_read_cb(nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data)
{
    // TODO:
    debugx("provider_read_cb - len: %d, stream_id: %d", length, stream_id);
    return 0;
}

static int _http2_header_cb(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
    perf__doh_socket_t *sock = (perf__doh_socket_t *)user_data;
    (void)flags;

    // // debugx("header_cb - type: %d, session_id: %d", frame->hd.type, frame->hd.stream_id);

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            self->http2->stream->stream_id == frame->hd.stream_id) {
            fwrite(name, 1, namelen, stderr);
            fprintf(stderr, ": ");
            fwrite(value, 1, valuelen, stderr);
            fprintf(stderr, "\n");
            
            break;
        }
    }
    return 0;
}

static int _http2_stream_close_cb(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
{
    (void)user_data;

    // TODO:
    // // debugx("close_cb - stream_id: %d", stream_id);
    
    if (nghttp2_session_get_stream_user_data(session, stream_id)) {
        // debugx("http2 session closed - stream_id: %d, error_code: %d", 
        //        stream_id, error_code);
        int ret;
        ret = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

        if (ret != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    return 0;
}

static int _http2_frame_recv_cb(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    perf__doh_socket_t *sock = (perf__doh_socket_t *)user_data;

    // TODO:
    // debugx("frame_recv_cb - type: %d, stream_id: %d", frame->hd.type, frame->hd.stream_id);
    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            const nghttp2_nv *nva = frame->headers.nva;
            if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
                for (size_t i = 0; i < frame->headers.nvlen; ++i) {
                    fwrite(nva[i].name, 1, nva[i].namelen, stderr);
                    fprintf(stderr, ": ");
                    fwrite(nva[i].value, 1, nva[i].valuelen, stderr);
                    fprintf(stderr, "\n");
                }
            }
        }
        break;
    case NGHTTP2_DATA: 
        // debugx("DATA frame received - flags: %d", frame->hd.flags);
        // we are interested in DATA frame which will carry the DNS response
        // NGHTTP2_FLAG_END_STREAM indicates that we have the data in full
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            // debugx("END_STREAM - copying to recvbuf\n");
            if (self->http2->dnsmsg_at > TCP_RECV_BUF_SIZE) {
                perf_log_warning("DNS response > TCP_RECV_BUF_SIZE");
                break;
            }

            /*
            fprintf(stderr, "dnsmsg: ");
            fwrite(self->http2->dnsmsg, 1, self->http2->dnsmsg_at, stderr);
            fprintf(stderr, "\n");
            */

            memset(self->http2->dnsmsg, 0, DNS_MSG_MAX_SIZE);
            self->http2->dnsmsg_completed = true;
            self->have_more = false;
        }
        break;
    case NGHTTP2_SETTINGS:
        // TODO: check if we need to set remote settings (only first SETTINGs frame)
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            // debugx("Settings ACK received\n");
        } else {
            // debugx("Settings FRAME received\n");
        }
        break;
    case NGHTTP2_RST_STREAM:
        // debugx(": RST_STREAM\n");
        break;
    case NGHTTP2_GOAWAY:
        // debugx(": GOAWAY\n");
        break;
    }
    
    return 0;
}

static int _http2_frame_send_cb(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
    (void)user_data;
    // TODO:
    // debugx("frame_send_cb - frame type: %d, stream_id: %d", frame->hd.type, frame->hd.stream_id);
    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        // debugx("headers cat: %d", frame->headers.cat);
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE ||
            frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            const nghttp2_nv *nva = frame->headers.nva;
            if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
                for (size_t i = 0; i < frame->headers.nvlen; ++i) {
                    fwrite(nva[i].name, 1, nva[i].namelen, stderr);
                    fprintf(stderr, ": ");
                    fwrite(nva[i].value, 1, nva[i].valuelen, stderr);
                    fprintf(stderr, "\n");
                }
            }
        }
        break;
    case NGHTTP2_SETTINGS:
        debugx("frame_send: nghttp2_settings, stream_id: %d", frame->hd.stream_id);
        const nghttp2_nv *nva = frame->headers.nva;
        if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
            for (size_t i = 0; i < frame->headers.nvlen; ++i) {
                fwrite(nva[i].name, 1, nva[i].namelen, stderr);
                fprintf(stderr, ": ");
                fwrite(nva[i].value, 1, nva[i].valuelen, stderr);
                fprintf(stderr, "\n");
            }
        }
        break;

    case NGHTTP2_RST_STREAM:
        // debugx(": RST_STREAM\n");
        break;
    case NGHTTP2_GOAWAY:
        // debugx(": GOAWAY\n");
        break;
    }
    
    return 0;
}

static int _http2_data_chunk_recv_cb(nghttp2_session* session, 
                                     uint8_t flags, 
                                     int32_t stream_id, 
                                     const uint8_t* data, 
                                     size_t len, void* user_data)
{
    perf__doh_socket_t *sock = (perf__doh_socket_t *)user_data;
    (void)flags;

    int ret;
    // debugx("data_chunk_recv_cb");
    if (nghttp2_session_get_stream_user_data(session, stream_id)) {
        // debugx("data_chunk length: %d\n", len);
        // fwrite(data, 1, len, stderr);
        // debugx("\n");

        if (self->http2->dnsmsg_at == 0) {
            // TODO: upper boundary check
            memcpy(self->http2->dnsmsg, data, len);
            self->http2->dnsmsg_at = len;
        } else {
            // TODO: boundary checks for self->recvbuf_at + len
            memcpy(self->http2->dnsmsg + self->http2->dnsmsg_at, data, len);
            self->http2->dnsmsg_at += len;
        }
    }
    
    // TODO: read incoming data and append to buf
    return 0;
}

static int _http2_init(struct perf__doh_socket* sock)
{
    debugx("_http2_init for qid: %d", sock->qid);
    struct URI uri;
    int ret = -1;
    nghttp2_session_callbacks* callbacks;
    nghttp2_option* option;

    ret = parse_uri(&uri, net_doh_uri);

    if (ret != 0) {
        perf_log_fatal("Failed to parse https URI");
    }
  
    self->http2 = http2_session_init();
    self->http2->stream = http2_stream_init(&uri);
    self->http2->max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;

    /* sets HTTP/2 callbacks */
    assert(nghttp2_session_callbacks_new(&callbacks) == 0);
    nghttp2_session_callbacks_set_send_callback(callbacks, _http2_send_cb);
    // nghttp2_session_callbacks_set_recv_callback(callbacks, _http2_recv_cb); // TODO: remove past debug
    nghttp2_session_callbacks_set_on_header_callback(callbacks, _http2_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, _http2_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, _http2_frame_recv_cb);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, _http2_frame_send_cb); // TODO: remove - debug
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, _http2_stream_close_cb);

    assert(nghttp2_option_new(&option) == 0);
    nghttp2_option_set_peer_max_concurrent_streams(option, self->http2->max_concurrent_streams);

    ret = nghttp2_session_client_new2(&self->http2->session, callbacks, self, option);

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);

    debugx("http2 session client ret: %d", ret);
    if (ret < 0) {
        free(self->http2);
        self->http2 = NULL;
    }

    memset(self->http2->dnsmsg, 0, DNS_MSG_MAX_SIZE);
    self->http2->dnsmsg_at = 0;
    self->http2->settings_sent = 0;
    self->http2->dnsmsg_completed = false;

    return ret;
}

static int _http2_send_settings(http2_session_t *session_data) {
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_CONCURRENT_STREAMS},
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535}
    };
    int ret = -1;

    ret = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               sizeof(iv) / sizeof(*iv));
    if (ret != 0) {
        perf_log_warning("Could not submit https2 SETTINGS: %s", nghttp2_strerror(ret));
        return ret;
    }

     debugx("sent connection headers/settings");

    return 0;
}

static ssize_t perf__doh_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    ssize_t n;
    ssize_t ret = 0;

    // read TLS data here instead of nghttp2_recv_callback
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

    // make sure we can process data
    if (self->is_ready &&
        self->http2 != NULL) {
        // this will be processed by nghttp2 callbacks
        // self->recvbuf holds the payload
        PERF_LOCK(&self->lock);
        ret = nghttp2_session_mem_recv(self->http2->session, 
                                       (uint8_t*) self->recvbuf + (self->at - n), 
                                       n);
 
        memset(self->recvbuf, 0, len);
    
        if (ret < 0) {
            perf_log_warning("nghttp2_session_mem_recv failed: %s", 
                            nghttp2_strerror((int) ret));

            http2_session_free(sock);       
            return -1;
        }

        // need to execute nghttp2_session_send if the receive ops triggered data frames 
        ret = nghttp2_session_send(self->http2->session);
        if (ret < 0) {
            http2_session_free(sock);
            PERF_UNLOCK(&self->lock);
            return -1;
        }

        PERF_UNLOCK(&self->lock);
    }
    
    PERF_LOCK(&self->lock);

    if (self->http2 &&
        self->http2->dnsmsg_completed) {
        // debugx("copying to recv buf - len: %d", self->http2->dnsmsg_at);
        memcpy(buf, self->http2->dnsmsg, self->http2->dnsmsg_at);
        PERF_UNLOCK(&self->lock);
        return self->http2->dnsmsg_at;
    } else {
        PERF_UNLOCK(&self->lock);
        errno = EAGAIN;
        return -1;
    }
}

static ssize_t perf__doh_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    int ret = -1;

    PERF_LOCK(&self->lock);
    self->qid = qid;
 
    if (self->is_ready) {
        // TODO: check doh_method and do *_{get,post}()
        ret = _submit_dns_query_get(sock, buf, len);
        PERF_UNLOCK(&self->lock);

        if (ret == 0) { // success
            return len;
        } else {
            return ret;
        }
    }

    PERF_UNLOCK(&self->lock);

    return len;
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

    if (self->is_ready &&
        self->http2 != NULL) {
        // do nghttp2 I/O send to flush outstanding frames
        int ret;
    
        ret = nghttp2_session_send(self->http2->session);
        if (ret != 0) {
            perf_log_printf("nghttp2_session_send failed: %s", nghttp2_strerror(ret));
            http2_session_free(sock);
            PERF_UNLOCK(&self->lock);
            return 0;
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

    const uint8_t *alpn = NULL;
    uint32_t alpn_len = 0;
 #ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_get0_next_proto_negotiated(self->ssl, &alpn, &alpn_len);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
        SSL_get0_alpn_selected(self->ssl, &alpn, &alpn_len);
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

    if (alpn == NULL || 
        alpn_len != 2 || 
        memcmp("h2", alpn, 2) != 0) {
        http2_session_free(sock);
        perf_log_fatal("failed to negotiate h2 proto.");
    }

    // guard against re-entrant http2_init
    if (!self->http2->settings_sent) {
        // send settings
        ret = _http2_send_settings(self->http2);
        if (ret != 0) {
            perf_log_printf("nghttp2_submit_settings failed: %s", nghttp2_strerror(ret));
            PERF_UNLOCK(&self->lock);
            return 0;
        }

        self->http2->settings_sent = true;
        // once we have TLS + http2 set, then we are ready to operate
    }
    
    PERF_UNLOCK(&self->lock);

    if (sock->event) {
        sock->event(sock, self->conn_event, perf_get_time() - self->conn_ts);
        self->conn_event = perf_socket_event_reconnected;
    }

    return 1;
}

static bool perf__doh_have_more(struct perf_net_socket* sock)
{
    return self->have_more;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
/* NPN TLS extension check */
static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  (void)ssl;
  (void)arg;

  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    perf_log_fatal("Server did not advertise %u", NGHTTP2_PROTO_VERSION_ID);
  }

  return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

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
        SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    #ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
    #endif /* !OPENSSL_NO_NEXTPROTONEG */

    #if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
    #endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
    }

    // init http/2 session
    ret = _http2_init(self);
    if (ret < 0) {
        // failed to initialise http2
        perf_log_fatal("nghttp2_init() failed to initialize: %d", ret);
    }

    perf__doh_connect(sock);

    return sock;
}