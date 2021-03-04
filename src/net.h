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

#ifndef PERF_NET_H
#define PERF_NET_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdbool.h>

#define TCP_RECV_BUF_SIZE (16 * 1024)
#define TCP_SEND_BUF_SIZE (4 * 1024)

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
    sock_dot
};

struct perf_net_socket;

typedef ssize_t (*perf_net_recv_t)(struct perf_net_socket* sock, void* buf, size_t len, int flags);
typedef ssize_t (*perf_net_sendto_t)(struct perf_net_socket* sock, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);
typedef int (*perf_net_close_t)(struct perf_net_socket* sock);
typedef int (*perf_net_sockeq_t)(struct perf_net_socket* sock, struct perf_net_socket* other);
typedef int (*perf_net_sockready_t)(struct perf_net_socket* sock, int pipe_fd, int64_t timeout);

struct perf_net_socket {
    enum perf_net_mode   mode;
    perf_net_recv_t      recv;
    perf_net_sendto_t    sendto;
    perf_net_close_t     close;
    perf_net_sockeq_t    sockeq;
    perf_net_sockready_t sockready;

    int  fd;
    bool is_sending; // indicate that the socket is still sending from buffers
    bool have_more; // indicate that the socket has more bytes to process in its recieve buffers
};

static inline ssize_t perf_net_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    return sock->recv(sock, buf, len, flags);
}

static inline ssize_t perf_net_sendto(struct perf_net_socket* sock, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
{
    return sock->sendto(sock, buf, len, flags, dest_addr, addrlen);
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

struct perf_net_socket* perf_net_opensocket(enum perf_net_mode mode, const perf_sockaddr_t* server, const perf_sockaddr_t* local, unsigned int offset, size_t bufsize);

struct perf_net_socket* perf_net_udp_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t);
struct perf_net_socket* perf_net_tcp_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t);
struct perf_net_socket* perf_net_dot_opensocket(const perf_sockaddr_t*, const perf_sockaddr_t*, size_t);

#endif
