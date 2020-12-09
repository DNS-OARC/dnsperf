/*
 * Copyright 2019-2020 OARC, Inc.
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
    sock_tls
};

struct perf_net_socket {
    enum perf_net_mode      mode;
    int                     fd, have_more, is_ready, flags, is_ssl_ready;
    char*                   recvbuf;
    size_t                  at, sending;
    char*                   sendbuf;
    struct sockaddr_storage dest_addr;
    socklen_t               addrlen;
    SSL*                    ssl;
    pthread_mutex_t         lock;
};

void      perf_sockaddr_fromin(perf_sockaddr_t* sockaddr, const struct in_addr* in, in_port_t port);
void      perf_sockaddr_fromin6(perf_sockaddr_t* sockaddr, const struct in6_addr* in, in_port_t port);
in_port_t perf_sockaddr_port(const perf_sockaddr_t* sockaddr);
void      perf_sockaddr_setport(perf_sockaddr_t* sockaddr, in_port_t port);
void      perf_sockaddr_format(const perf_sockaddr_t* sockaddr, char* buf, size_t len);

ssize_t perf_net_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags);
ssize_t perf_net_sendto(struct perf_net_socket* sock, const void* buf, size_t len, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen);

int perf_net_close(struct perf_net_socket* sock);
int perf_net_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b);

int perf_net_parsefamily(const char* family);

void perf_net_parseserver(int family, const char* name, unsigned int port, perf_sockaddr_t* addr);
void perf_net_parselocal(int family, const char* name, unsigned int port, perf_sockaddr_t* addr);

struct perf_net_socket perf_net_opensocket(enum perf_net_mode mode, const perf_sockaddr_t* server, const perf_sockaddr_t* local, unsigned int offset, int bufsize);

enum perf_net_mode perf_net_parsemode(const char* mode);

int perf_net_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout);

#endif
