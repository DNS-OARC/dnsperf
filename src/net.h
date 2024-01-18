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

#ifndef PERF_NET_H
#define PERF_NET_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdbool.h>

#define TCP_RECV_BUF_SIZE (65535 + 2)
#define TCP_SEND_BUF_SIZE (65535 + 2)

struct perf_sockaddr {
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } sa;
    socklen_t length;
};
typedef struct perf_sockaddr perf_sockaddr_t;

enum perf_net_mode {
    sock_none,
    sock_file,
    sock_pipe,
    sock_udp,
    sock_tcp,
    sock_dot,
    sock_doh
};

struct perf_net_socket;

typedef ssize_t (*perf_net_recv_t)(struct perf_net_socket* sock, void* buf, size_t len, int flags);
typedef ssize_t (*perf_net_sendto_t)(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
typedef int (*perf_net_close_t)(struct perf_net_socket* sock);
typedef int (*perf_net_sockeq_t)(struct perf_net_socket* sock, struct perf_net_socket* other);

/* sockready return:
 * -1: socket readiness timed out / canceled / interrupted or unknown error
 * 0: Socket is not ready, may still be connecting, negotiating or sending
 * 1: Socket is ready and can be used for sending to
 */
typedef int (*perf_net_sockready_t)(struct perf_net_socket* sock, int pipe_fd, int64_t timeout);

/* Indicates if there are more data to be read in buffers of the transport */
typedef bool (*perf_net_have_more_t)(struct perf_net_socket* sock);

/* Callback for when a query has been sent if it was delayed due to partily sent or reconnection */
typedef void (*perf_net_sent_cb_t)(struct perf_net_socket* sock, uint16_t qid);

typedef enum perf_socket_event {
    perf_socket_event_connecting,
    perf_socket_event_connected,
    perf_socket_event_reconnecting,
    perf_socket_event_reconnected
} perf_socket_event_t;
/* Callback for socket events related to connection oriented protocols, for statistics */
typedef void (*perf_net_event_cb_t)(struct perf_net_socket* sock, perf_socket_event_t event, uint64_t elapsed_time);

typedef void (*perf_net_num_queries_per_conn_t)(struct perf_net_socket* sock, size_t num_queries_per_conn, size_t timeout);

struct perf_net_socket {
    void* data; /* user data */

    enum perf_net_mode   mode;
    perf_net_recv_t      recv;
    perf_net_sendto_t    sendto;
    perf_net_close_t     close;
    perf_net_sockeq_t    sockeq;
    perf_net_sockready_t sockready;
    perf_net_have_more_t have_more;

    perf_net_num_queries_per_conn_t num_queries_per_conn;

    /*
     * Not set by protocol, set by caller.
     * May be 0 if caller don't care.
     * MUST NOT be called from sendto(), only called if query is delayed in some way.
     */
    perf_net_sent_cb_t sent;

    /* Used if caller want info on connection oriented events */
    perf_net_event_cb_t event;

    /*
     * The system file descriptor that is used for transport, this is used
     * in os functions to poll/wait for read/write.
     */
    int fd;
};

static inline ssize_t perf_net_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    return sock->recv(sock, buf, len, flags);
}

static inline ssize_t perf_net_sendto(struct perf_net_socket* sock, uint16_t qid, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    return sock->sendto(sock, qid, buf, len, flags, dest_addr, addrlen);
}

static inline int perf_net_close(struct perf_net_socket* sock)
{
    return sock->close(sock);
}

static inline int perf_net_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    assert(sock_a);
    assert(sock_b);
    assert(sock_a->mode == sock_b->mode);
    return sock_a->sockeq(sock_a, sock_b);
}

static inline int perf_net_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    return sock->sockready(sock, pipe_fd, timeout);
}

static inline int perf_net_have_more(struct perf_net_socket* sock)
{
    return sock->have_more ? sock->have_more(sock) : false;
}

enum perf_net_mode perf_net_parsemode(const char* mode);

int perf_net_parsefamily(const char* family);

void perf_net_parseserver(int family, const char* name, unsigned int port, perf_sockaddr_t* addr);
void perf_net_parselocal(int family, const char* name, unsigned int port, perf_sockaddr_t* addr);

void      perf_sockaddr_fromin(perf_sockaddr_t* sockaddr, const struct in_addr* in, in_port_t port);
void      perf_sockaddr_fromin6(perf_sockaddr_t* sockaddr, const struct in6_addr* in, in_port_t port);
in_port_t perf_sockaddr_port(const perf_sockaddr_t* sockaddr);
void      perf_sockaddr_setport(perf_sockaddr_t* sockaddr, in_port_t port);
void      perf_sockaddr_format(const perf_sockaddr_t* sockaddr, char* buf, size_t len);

static inline int perf_sockaddr_isinet6(const perf_sockaddr_t* sockaddr)
{
    return sockaddr->sa.sa.sa_family == AF_INET6;
}

struct perf_net_socket* perf_net_opensocket(enum perf_net_mode mode, const perf_sockaddr_t* server, const perf_sockaddr_t* local, unsigned int offset, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event);

struct perf_net_socket* perf_net_udp_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event);
struct perf_net_socket* perf_net_tcp_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event);
struct perf_net_socket* perf_net_dot_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event);
struct perf_net_socket* perf_net_doh_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event);

#define DEFAULT_DOH_URI "https://localhost/dns-query"
#define DEFAULT_DOH_METHOD "GET"

void perf_net_doh_parse_uri(const char*);
void perf_net_doh_parse_method(const char*);
void perf_net_doh_set_max_concurrent_streams(size_t);

void perf_net_stats_init(enum perf_net_mode);
void perf_net_stats_compile(enum perf_net_mode, struct perf_net_socket*);
void perf_net_stats_print(enum perf_net_mode);
void perf_net_doh_stats_init();
void perf_net_doh_stats_compile(struct perf_net_socket*);
void perf_net_doh_stats_print();

extern const char* perf_net_tls_sni;

#endif
