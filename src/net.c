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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "log.h"
#include "net.h"
#include "opt.h"
#include "os.h"
#include "strerror.h"

#define TCP_RECV_BUF_SIZE (16 * 1024)
#define TCP_SEND_BUF_SIZE (4 * 1024)

static SSL_CTX* ssl_ctx = 0;

int perf_net_parsefamily(const char* family)
{
    if (family == NULL || strcmp(family, "any") == 0)
        return AF_UNSPEC;
    else if (strcmp(family, "inet") == 0)
        return AF_INET;
#ifdef AF_INET6
    else if (strcmp(family, "inet6") == 0)
        return AF_INET6;
#endif
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
        return sockaddr->sa.sin.sin_port;
    case AF_INET6:
        return sockaddr->sa.sin6.sin6_port;
    default:
        break;
    }
    return 0;
}

void perf_sockaddr_setport(perf_sockaddr_t* sockaddr, in_port_t port)
{
    switch (sockaddr->sa.sa.sa_family) {
    case AF_INET:
        sockaddr->sa.sin.sin_port = port;
        break;
    case AF_INET6:
        sockaddr->sa.sin6.sin6_port = port;
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

    if (port == 0) {
        fprintf(stderr, "server port cannot be 0\n");
        perf_opt_usage();
        exit(1);
    }

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

struct perf_net_socket perf_net_opensocket(enum perf_net_mode mode, const perf_sockaddr_t* server, const perf_sockaddr_t* local, unsigned int offset, int bufsize)
{
    int                    family;
    perf_sockaddr_t        tmp;
    int                    port;
    int                    ret;
    int                    flags;
    struct perf_net_socket sock = { .mode = mode, .is_ready = 1 };

    family = server->sa.sa.sa_family;

    if (local->sa.sa.sa_family != family) {
        perf_log_fatal("server and local addresses have different families");
    }

    switch (mode) {
    case sock_udp:
        sock.fd = socket(family, SOCK_DGRAM, 0);
        break;
    case sock_tls:
        if (pthread_mutex_init(&sock.lock, 0)) {
            perf_log_fatal("pthread_mutex_init() failed");
        }
        if ((sock.fd = socket(family, SOCK_STREAM, 0)) < 0) {
            char __s[256];
            perf_log_fatal("socket: %s", perf_strerror_r(errno, __s, sizeof(__s)));
        }
        if (!ssl_ctx) {
#ifdef HAVE_TLS_CLIENT_METHOD
            if (!(ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
#else
            if (!(ssl_ctx = SSL_CTX_new(SSLv23_client_method()))) {
#endif
                perf_log_fatal("SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(), 0));
            }
        }
        if (!(sock.ssl = SSL_new(ssl_ctx))) {
            perf_log_fatal("SSL_new(): %s", ERR_error_string(ERR_get_error(), 0));
        }
        if (!(ret = SSL_set_fd(sock.ssl, sock.fd))) {
            perf_log_fatal("SSL_set_fd(): %s", ERR_error_string(SSL_get_error(sock.ssl, ret), 0));
        }
        break;
    case sock_tcp:
        sock.fd = socket(family, SOCK_STREAM, 0);
        break;
    default:
        perf_log_fatal("perf_net_opensocket(): invalid mode");
    }

    if (sock.fd == -1) {
        char __s[256];
        perf_log_fatal("socket: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

#if defined(AF_INET6) && defined(IPV6_V6ONLY)
    if (family == AF_INET6) {
        int on = 1;

        if (setsockopt(sock.fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
            perf_log_warning("setsockopt(IPV6_V6ONLY) failed");
        }
    }
#endif

    tmp  = *local;
    port = perf_sockaddr_port(&tmp);
    if (port != 0 && offset != 0) {
        port += offset;
        if (port >= 0xFFFF)
            perf_log_fatal("port %d out of range", port);
        perf_sockaddr_setport(&tmp, port);
    }

    if (bind(sock.fd, &tmp.sa.sa, tmp.length) == -1) {
        char __s[256];
        perf_log_fatal("bind: %s", perf_strerror_r(errno, __s, sizeof(__s)));
    }

    if (bufsize > 0) {
        bufsize *= 1024;

        ret = setsockopt(sock.fd, SOL_SOCKET, SO_RCVBUF,
            &bufsize, sizeof(bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_RCVBUF) failed");

        ret = setsockopt(sock.fd, SOL_SOCKET, SO_SNDBUF,
            &bufsize, sizeof(bufsize));
        if (ret < 0)
            perf_log_warning("setsockbuf(SO_SNDBUF) failed");
    }

    flags = fcntl(sock.fd, F_GETFL, 0);
    if (flags < 0)
        perf_log_fatal("fcntl(F_GETFL)");
    ret = fcntl(sock.fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
        perf_log_fatal("fcntl(F_SETFL)");

    if (mode == sock_tcp || mode == sock_tls) {
        if (connect(sock.fd, &server->sa.sa, server->length)) {
            if (errno == EINPROGRESS) {
                sock.is_ready = 0;
            } else {
                char __s[256];
                perf_log_fatal("connect() failed: %s", perf_strerror_r(errno, __s, sizeof(__s)));
            }
        }
        sock.recvbuf   = malloc(TCP_RECV_BUF_SIZE);
        sock.at        = 0;
        sock.have_more = 0;
        sock.sendbuf   = malloc(TCP_SEND_BUF_SIZE);
        if (!sock.recvbuf || !sock.sendbuf) {
            perf_log_fatal("perf_net_opensocket() failed: unable to allocate buffers");
        }
    }

    return sock;
}

ssize_t perf_net_recv(struct perf_net_socket* sock, void* buf, size_t len, int flags)
{
    switch (sock->mode) {
    case sock_tls: {
        ssize_t  n;
        uint16_t dnslen, dnslen2;

        if (!sock->have_more) {
            if (pthread_mutex_lock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_lock() failed");
            }
            if (!sock->is_ready) {
                if (pthread_mutex_unlock(&sock->lock)) {
                    perf_log_fatal("pthread_mutex_unlock() failed");
                }
                errno = EAGAIN;
                return -1;
            }

            n = SSL_read(sock->ssl, sock->recvbuf + sock->at, TCP_RECV_BUF_SIZE - sock->at);
            if (n < 0) {
                int err = SSL_get_error(sock->ssl, n);
                if (pthread_mutex_unlock(&sock->lock)) {
                    perf_log_fatal("pthread_mutex_unlock() failed");
                }
                if (err == SSL_ERROR_WANT_READ) {
                    errno = EAGAIN;
                } else {
                    errno = EBADF;
                }
                return -1;
            }
            if (pthread_mutex_unlock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_unlock() failed");
            }

            sock->at += n;
            if (sock->at < 3) {
                errno = EAGAIN;
                return -1;
            }
        }

        memcpy(&dnslen, sock->recvbuf, 2);
        dnslen = ntohs(dnslen);
        if (sock->at < dnslen + 2) {
            errno = EAGAIN;
            return -1;
        }
        memcpy(buf, sock->recvbuf + 2, len < dnslen ? len : dnslen);
        memmove(sock->recvbuf, sock->recvbuf + 2 + dnslen, sock->at - 2 - dnslen);
        sock->at -= 2 + dnslen;

        if (sock->at > 2) {
            memcpy(&dnslen2, sock->recvbuf, 2);
            dnslen2 = ntohs(dnslen2);
            if (sock->at >= dnslen2 + 2) {
                sock->have_more = 1;
                return dnslen;
            }
        }

        sock->have_more = 0;
        return dnslen;
    }
    case sock_tcp: {
        ssize_t  n;
        uint16_t dnslen, dnslen2;

        if (!sock->have_more) {
            n = recv(sock->fd, sock->recvbuf + sock->at, TCP_RECV_BUF_SIZE - sock->at, flags);
            if (n < 0) {
                if (errno == ECONNRESET) {
                    // Treat connection reset like try again until reconnection features are in
                    errno = EAGAIN;
                }
                return n;
            }
            sock->at += n;
            if (sock->at < 3) {
                errno = EAGAIN;
                return -1;
            }
        }

        memcpy(&dnslen, sock->recvbuf, 2);
        dnslen = ntohs(dnslen);
        if (sock->at < dnslen + 2) {
            errno = EAGAIN;
            return -1;
        }
        memcpy(buf, sock->recvbuf + 2, len < dnslen ? len : dnslen);
        memmove(sock->recvbuf, sock->recvbuf + 2 + dnslen, sock->at - 2 - dnslen);
        sock->at -= 2 + dnslen;

        if (sock->at > 2) {
            memcpy(&dnslen2, sock->recvbuf, 2);
            dnslen2 = ntohs(dnslen2);
            if (sock->at >= dnslen2 + 2) {
                sock->have_more = 1;
                return dnslen;
            }
        }

        sock->have_more = 0;
        return dnslen;
    }
    default:
        break;
    }

    return recv(sock->fd, buf, len, flags);
}

ssize_t perf_net_sendto(struct perf_net_socket* sock, const void* buf, size_t len, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen)
{
    switch (sock->mode) {
    case sock_tls: {
        size_t send = len < TCP_SEND_BUF_SIZE - 2 ? len : (TCP_SEND_BUF_SIZE - 2);
        // TODO: We only send what we can send, because we can't continue sending
        uint16_t dnslen = htons(send);
        ssize_t  n;

        memcpy(sock->sendbuf, &dnslen, 2);
        memcpy(sock->sendbuf + 2, buf, send);
        if (pthread_mutex_lock(&sock->lock)) {
            perf_log_fatal("pthread_mutex_lock() failed");
        }
        n = SSL_write(sock->ssl, sock->sendbuf, send + 2);
        if (n < 0) {
            perf_log_warning("SSL_write(): %s", ERR_error_string(SSL_get_error(sock->ssl, n), 0));
            errno = EBADF;
        }
        if (pthread_mutex_unlock(&sock->lock)) {
            perf_log_fatal("pthread_mutex_unlock() failed");
        }

        if (n > 0 && n < send + 2) {
            sock->sending = n;
            sock->flags   = flags;
            memcpy(&sock->dest_addr, dest_addr, addrlen);
            sock->addrlen  = addrlen;
            sock->is_ready = 0;
            errno          = EINPROGRESS;
            return -1;
        }

        return n > 0 ? n - 2 : n;
    }
    case sock_tcp: {
        size_t send = len < TCP_SEND_BUF_SIZE - 2 ? len : (TCP_SEND_BUF_SIZE - 2);
        // TODO: We only send what we can send, because we can't continue sending
        uint16_t dnslen = htons(send);
        ssize_t  n;

        memcpy(sock->sendbuf, &dnslen, 2);
        memcpy(sock->sendbuf + 2, buf, send);
        n = sendto(sock->fd, sock->sendbuf, send + 2, flags, dest_addr, addrlen);

        if (n > 0 && n < send + 2) {
            sock->sending = n;
            sock->flags   = flags;
            memcpy(&sock->dest_addr, dest_addr, addrlen);
            sock->addrlen  = addrlen;
            sock->is_ready = 0;
            errno          = EINPROGRESS;
            return -1;
        }

        return n > 0 ? n - 2 : n;
    }
    default:
        break;
    }
    return sendto(sock->fd, buf, len, flags, dest_addr, addrlen);
}

int perf_net_close(struct perf_net_socket* sock)
{
    return close(sock->fd);
}

int perf_net_sockeq(struct perf_net_socket* sock_a, struct perf_net_socket* sock_b)
{
    return sock_a->fd == sock_b->fd;
}

enum perf_net_mode perf_net_parsemode(const char* mode)
{
    if (!strcmp(mode, "udp")) {
        return sock_udp;
    } else if (!strcmp(mode, "tcp")) {
        return sock_tcp;
    } else if (!strcmp(mode, "tls")) {
        return sock_tls;
    }

    perf_log_warning("invalid socket mode");
    perf_opt_usage();
    exit(1);
}

int perf_net_sockready(struct perf_net_socket* sock, int pipe_fd, int64_t timeout)
{
    if (sock->is_ready) {
        return 1;
    }

    switch (sock->mode) {
    case sock_tls: {
        int ret;

        if (sock->sending) {
            uint16_t dnslen;
            ssize_t  n;

            memcpy(&dnslen, sock->sendbuf, 2);
            dnslen = ntohs(dnslen);
            if (pthread_mutex_lock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_lock() failed");
            }
            n = SSL_write(sock->ssl, sock->sendbuf + sock->sending, dnslen + 2 - sock->sending);
            if (n < 1) {
                if (n < 0) {
                    perf_log_warning("SSL_write(): %s", ERR_error_string(SSL_get_error(sock->ssl, n), 0));
                    errno = EBADF;
                }
                if (pthread_mutex_unlock(&sock->lock)) {
                    perf_log_fatal("pthread_mutex_unlock() failed");
                }
                return -1;
            }
            if (pthread_mutex_unlock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_unlock() failed");
            }
            sock->sending += n;
            if (sock->sending < dnslen + 2) {
                errno = EINPROGRESS;
                return -1;
            }
            sock->sending  = 0;
            sock->is_ready = 1;
            return 1;
        }

        if (!sock->is_ssl_ready) {
            switch (perf_os_waituntilanywritable(sock, 1, pipe_fd, timeout)) {
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
            }
            }
            sock->is_ssl_ready = 1;
        }

        if (pthread_mutex_lock(&sock->lock)) {
            perf_log_fatal("pthread_mutex_lock() failed");
        }
        ret = SSL_connect(sock->ssl);
        if (!ret) {
            perf_log_warning("SSL_connect(): %s", ERR_error_string(SSL_get_error(sock->ssl, ret), 0));
            if (pthread_mutex_unlock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_unlock() failed");
            }
            return -1;
        }
        if (ret < 0) {
            int err = SSL_get_error(sock->ssl, ret);
            if (pthread_mutex_unlock(&sock->lock)) {
                perf_log_fatal("pthread_mutex_unlock() failed");
            }
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return 0;
            }
            perf_log_warning("SSL_connect(): %s", ERR_error_string(err, 0));
            return -1;
        }
        sock->is_ready = 1;
        if (pthread_mutex_unlock(&sock->lock)) {
            perf_log_fatal("pthread_mutex_unlock() failed");
        }
        return 1;
    }
    case sock_tcp:
        if (sock->sending) {
            uint16_t dnslen;
            ssize_t  n;

            memcpy(&dnslen, sock->sendbuf, 2);
            dnslen = ntohs(dnslen);
            n      = sendto(sock->fd, sock->sendbuf + sock->sending, dnslen + 2 - sock->sending, sock->flags, (struct sockaddr*)&sock->dest_addr, sock->addrlen);
            if (n < 1) {
                return -1;
            }
            sock->sending += n;
            if (sock->sending < dnslen + 2) {
                errno = EINPROGRESS;
                return -1;
            }
            sock->sending  = 0;
            sock->is_ready = 1;
            return 1;
        }

        switch (perf_os_waituntilanywritable(sock, 1, pipe_fd, timeout)) {
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
            sock->is_ready = 1;
            return 1;
        }
        }
        break;
    default:
        break;
    }

    return -1;
}
