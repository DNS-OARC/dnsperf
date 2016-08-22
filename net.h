/*
 * Copyright (C) 2000-2001,2004-2015 Nominum, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PERF_NET_H
#define PERF_NET_H 1

int
perf_net_parsefamily(const char *family);

void
perf_net_parseserver(int family, const char *name, unsigned int port,
                     isc_sockaddr_t *addr);

void
perf_net_parselocal(int family, const char *name, unsigned int port,
                    isc_sockaddr_t *addr);

int
perf_net_opensocket(const isc_sockaddr_t *server, const isc_sockaddr_t *local,
                    unsigned int offset, int bufsize);

#endif
