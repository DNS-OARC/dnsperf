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
#include "opt.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>

const char* perf_net_tls_sni = 0;

enum perf_net_mode perf_net_parsemode(const char* mode)
{
    if (!strcmp(mode, "udp")) {
        return sock_udp;
    } else if (!strcmp(mode, "tcp")) {
        return sock_tcp;
    } else if (!strcmp(mode, "tls") || !strcmp(mode, "dot")) {
        return sock_dot;
    } else if (!strcmp(mode, "doh")) {
        return sock_doh;
    }

    perf_log_warning("invalid socket mode");
    perf_opt_usage();
    exit(1);
}

int perf_net_parsefamily(const char* family)
{
    if (family == NULL || strcmp(family, "any") == 0)
        return AF_UNSPEC;
    else if (strcmp(family, "inet") == 0)
        return AF_INET;
    else if (strcmp(family, "inet6") == 0)
        return AF_INET6;
    else {
        fprintf(stderr, "invalid family %s\n", family);
        perf_opt_usage();
        exit(1);
    }
}

void perf_sockaddr_fromin(perf_sockaddr_t* sockaddr, const struct in_addr* in, in_port_t port)
{
    memset(sockaddr, 0, sizeof(*sockaddr));
    sockaddr->sa.sin.sin_family = AF_INET;
    sockaddr->sa.sin.sin_addr   = *in;
    sockaddr->sa.sin.sin_port   = htons(port);
    sockaddr->length            = sizeof(sockaddr->sa.sin);
}

void perf_sockaddr_fromin6(perf_sockaddr_t* sockaddr, const struct in6_addr* in, in_port_t port)
{
    memset(sockaddr, 0, sizeof(*sockaddr));
    sockaddr->sa.sin6.sin6_family = AF_INET6;
    sockaddr->sa.sin6.sin6_addr   = *in;
    sockaddr->sa.sin6.sin6_port   = htons(port);
    sockaddr->length              = sizeof(sockaddr->sa.sin6);
}

in_port_t perf_sockaddr_port(const perf_sockaddr_t* sockaddr)
{
    switch (sockaddr->sa.sa.sa_family) {
    case AF_INET:
        return ntohs(sockaddr->sa.sin.sin_port);
    case AF_INET6:
        return ntohs(sockaddr->sa.sin6.sin6_port);
    default:
        break;
    }
    return 0;
}

void perf_sockaddr_setport(perf_sockaddr_t* sockaddr, in_port_t port)
{
    switch (sockaddr->sa.sa.sa_family) {
    case AF_INET:
        sockaddr->sa.sin.sin_port = htons(port);
        break;
    case AF_INET6:
        sockaddr->sa.sin6.sin6_port = htons(port);
        break;
    default:
        break;
    }
}

void perf_sockaddr_format(const perf_sockaddr_t* sockaddr, char* buf, size_t len)
{
    const void* src;

    *buf = 0;

    switch (sockaddr->sa.sa.sa_family) {
    case AF_INET:
        src = &sockaddr->sa.sin.sin_addr;
        break;
    case AF_INET6:
        src = &sockaddr->sa.sin6.sin6_addr;
        break;
    default:
        return;
    }

    (void)inet_ntop(sockaddr->sa.sa.sa_family, src, buf, len);
}

void perf_net_parseserver(int family, const char* name, unsigned int port, perf_sockaddr_t* addr)
{
    struct addrinfo* ai;

    if (getaddrinfo(name, 0, 0, &ai) == 0) {
        struct addrinfo* a;

        for (a = ai; a; a = a->ai_next) {
            if (a->ai_family == family || family == AF_UNSPEC) {
                switch (a->ai_family) {
                case AF_INET:
                    perf_sockaddr_fromin(addr, &((struct sockaddr_in*)a->ai_addr)->sin_addr, port);
                    break;
                case AF_INET6:
                    perf_sockaddr_fromin6(addr, &((struct sockaddr_in6*)a->ai_addr)->sin6_addr, port);
                    break;
                default:
                    continue;
                }

                freeaddrinfo(ai);
                return;
            }
        }
        freeaddrinfo(ai);
    }

    fprintf(stderr, "invalid server address %s\n", name);
    perf_opt_usage();
    exit(1);
}

void perf_net_parselocal(int family, const char* name, unsigned int port,
    perf_sockaddr_t* addr)
{
    struct in_addr  in4a;
    struct in6_addr in6a;

    if (name == NULL) {
        switch (family) {
        case AF_INET:
            in4a.s_addr = INADDR_ANY;
            perf_sockaddr_fromin(addr, &in4a, port);
            return;
        case AF_INET6:
            perf_sockaddr_fromin6(addr, &in6addr_any, port);
            return;
        default:
            break;
        }
    } else if (inet_pton(AF_INET, name, &in4a) == 1) {
        perf_sockaddr_fromin(addr, &in4a, port);
        return;
    } else if (inet_pton(AF_INET6, name, &in6a) == 1) {
        perf_sockaddr_fromin6(addr, &in6a, port);
        return;
    }

    fprintf(stderr, "invalid local address %s\n", name);
    perf_opt_usage();
    exit(1);
}

struct perf_net_socket* perf_net_opensocket(enum perf_net_mode mode, const perf_sockaddr_t* server, const perf_sockaddr_t* local, unsigned int offset, size_t bufsize, void* data, perf_net_sent_cb_t sent, perf_net_event_cb_t event)
{
    int             port;
    perf_sockaddr_t tmp;

    if (server->sa.sa.sa_family != local->sa.sa.sa_family) {
        perf_log_fatal("server and local addresses have different families");
    }

    tmp  = *local;
    port = perf_sockaddr_port(&tmp);
    if (port != 0 && offset != 0) {
        port += offset;
        if (port >= 0xFFFF)
            perf_log_fatal("port %d out of range", port);
        perf_sockaddr_setport(&tmp, port);
    }

    switch (mode) {
    case sock_udp:
        return perf_net_udp_opensocket(server, &tmp, bufsize, data, sent, event);
    case sock_tcp:
        return perf_net_tcp_opensocket(server, &tmp, bufsize, data, sent, event);
    case sock_dot:
        return perf_net_dot_opensocket(server, &tmp, bufsize, data, sent, event);
    case sock_doh:
        return perf_net_doh_opensocket(server, &tmp, bufsize, data, sent, event);
    default:
        perf_log_fatal("perf_net_opensocket(): invalid mode");
    }

    return 0;
}

void perf_net_stats_init(enum perf_net_mode mode)
{
    switch (mode) {
    case sock_doh:
        perf_net_doh_stats_init();
    default:
        break;
    }
}

void perf_net_stats_compile(enum perf_net_mode mode, struct perf_net_socket* sock)
{
    switch (mode) {
    case sock_doh:
        perf_net_doh_stats_compile(sock);
    default:
        break;
    }
}

void perf_net_stats_print(enum perf_net_mode mode)
{
    switch (mode) {
    case sock_doh:
        perf_net_doh_stats_print();
    default:
        break;
    }
}
