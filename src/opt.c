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

#include "opt.h"

#include "log.h"
#include "util.h"
#include "result.h"

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>

#define MAX_OPTS 64
#define LINE_LENGTH 80

typedef struct {
    char           c;
    perf_opttype_t type;
    const char*    desc;
    const char*    help;
    const char*    defval;
    char           defvalbuf[512];
    union {
        void*         valp;
        char**        stringp;
        bool*         boolp;
        unsigned int* uintp;
        uint64_t*     uint64p;
        double*       doublep;
        in_port_t*    portp;
    } u;
} opt_t;

typedef struct long_opt long_opt_t;
struct long_opt {
    long_opt_t*    next;
    const char*    name;
    perf_opttype_t type;
    const char*    desc;
    const char*    help;
    const char*    defval;
    char           defvalbuf[512];
    union {
        void*         valp;
        char**        stringp;
        bool*         boolp;
        unsigned int* uintp;
        uint64_t*     uint64p;
        double*       doublep;
        in_port_t*    portp;
    } u;
};

static opt_t        opts[MAX_OPTS];
static long_opt_t*  longopts = 0;
static unsigned int nopts;
static char         optstr[MAX_OPTS * 2 + 2 + 1] = { 0 };
extern const char*  progname;

void perf_opt_add(char c, perf_opttype_t type, const char* desc, const char* help,
    const char* defval, void* valp)
{
    opt_t* opt;

    if (nopts == MAX_OPTS) {
        perf_log_fatal("too many defined options");
        return;
    }
    opt       = &opts[nopts++];
    opt->c    = c;
    opt->type = type;
    opt->desc = desc;
    opt->help = help;
    if (defval != NULL) {
        if (strlen(defval) > sizeof(opt->defvalbuf) - 1) {
            perf_log_fatal("perf_opt_add(): defval too large");
            return;
        }
        strncpy(opt->defvalbuf, defval, sizeof(opt->defvalbuf));
        opt->defvalbuf[sizeof(opt->defvalbuf) - 1] = 0;
        opt->defval                                = opt->defvalbuf;
    } else {
        opt->defval = NULL;
    }
    opt->u.valp = valp;

    char newoptstr[sizeof(optstr) + 2];
    snprintf(newoptstr, sizeof(newoptstr), "%s%c%s", optstr, c, (type == perf_opt_boolean ? "" : ":"));
    memcpy(optstr, newoptstr, sizeof(optstr) - 1);
    optstr[sizeof(optstr) - 1] = 0;
}

void perf_long_opt_add(const char* name, perf_opttype_t type, const char* desc, const char* help, const char* defval, void* valp)
{
    long_opt_t* opt = calloc(1, sizeof(long_opt_t));

    if (!opt) {
        perf_log_fatal("perf_long_opt_add(): out of memory");
        return;
    }

    opt->name = name;
    opt->type = type;
    opt->desc = desc;
    opt->help = help;
    if (defval != NULL) {
        if (strlen(defval) > sizeof(opt->defvalbuf) - 1) {
            perf_log_fatal("perf_opt_add(): defval too large");
            free(opt); // fix clang scan-build
            return;
        }
        strncpy(opt->defvalbuf, defval, sizeof(opt->defvalbuf));
        opt->defvalbuf[sizeof(opt->defvalbuf) - 1] = 0;
        opt->defval                                = opt->defvalbuf;
    } else {
        opt->defval = NULL;
    }
    opt->u.valp = valp;

    opt->next = longopts;
    longopts  = opt;
}

void perf_opt_usage(void)
{
    unsigned int prefix_len, position, arg_len, i, j;

    prefix_len = fprintf(stderr, "Usage: %s", progname);
    position   = prefix_len;
    for (i = 0; i < nopts; i++) {
        arg_len = 6;
        if (opts[i].desc != NULL)
            arg_len += strlen(opts[i].desc) + 1;
        if (LINE_LENGTH - position - 1 < arg_len) {
            fprintf(stderr, "\n");
            for (j = 0; j < prefix_len; j++)
                fprintf(stderr, " ");
            position = prefix_len;
        }
        fprintf(stderr, " [-%c", opts[i].c);
        if (opts[i].desc != NULL)
            fprintf(stderr, " %s", opts[i].desc);
        fprintf(stderr, "]");
        position += arg_len;
    }
    fprintf(stderr, "\n");

    for (i = 0; i < nopts; i++) {
        fprintf(stderr, "  -%c %s", opts[i].c, opts[i].help);
        if (opts[i].defval)
            fprintf(stderr, " (default: %s)", opts[i].defval);
        fprintf(stderr, "\n");
    }
}

static uint32_t
parse_uint(const char* desc, const char* str,
    unsigned int min, unsigned int max)
{
    unsigned long int val;
    uint32_t          ret;
    char*             endptr = 0;

    errno = 0;
    val   = strtoul(str, &endptr, 10);
    if (!errno && str && *str && endptr && !*endptr && val <= UINT32_MAX) {
        ret = (uint32_t)val;
        if (ret >= min && ret <= max) {
            return ret;
        }
    }

    fprintf(stderr, "invalid %s: %s\n", desc, str);
    perf_opt_usage();
    exit(1);
}

static double
parse_double(const char* desc, const char* str)
{
    const char* s;
    char        c;
    bool        seen_dot = false;

    s = str;
    while (*s != 0) {
        c = *s++;
        if (c == '.') {
            if (seen_dot)
                goto fail;
            seen_dot = true;
        } else if (c < '0' || c > '9') {
            goto fail;
        }
    }

    return atof(str);

fail:
    fprintf(stderr, "invalid %s: %s\n", desc, str);
    perf_opt_usage();
    exit(1);
}

static uint64_t
parse_timeval(const char* desc, const char* str)
{
    return MILLION * parse_double(desc, str);
}

static int perf_opt_long_parse(char* optarg)
{
    ssize_t optlen;
    char*   arg;

    if ((arg = strchr(optarg, '='))) {
        optlen = arg - optarg;
        arg++;
        if (optlen < 1 || !strlen(arg)) {
            return -1;
        }
    } else {
        optlen = strlen(optarg);
    }

    long_opt_t* opt = longopts;
    while (opt) {
        if (!strncmp(optarg, opt->name, optlen)) {
            switch (opt->type) {
            case perf_opt_string:
                if (!arg) {
                    return -1;
                }
                *opt->u.stringp = arg;
                break;
            case perf_opt_boolean:
                *opt->u.boolp = true;
                break;
            case perf_opt_uint:
                if (!arg) {
                    return -1;
                }
                *opt->u.uintp = parse_uint(opt->desc, arg, 1, 0xFFFFFFFF);
                break;
            case perf_opt_zpint:
                if (!arg) {
                    return -1;
                }
                *opt->u.uintp = parse_uint(opt->desc, arg, 0, 0xFFFFFFFF);
                break;
            case perf_opt_timeval:
                if (!arg) {
                    return -1;
                }
                *opt->u.uint64p = parse_timeval(opt->desc, arg);
                break;
            case perf_opt_double:
                if (!arg) {
                    return -1;
                }
                *opt->u.doublep = parse_double(opt->desc, arg);
                break;
            case perf_opt_port:
                if (!arg) {
                    return -1;
                }
                *opt->u.portp = parse_uint(opt->desc, arg, 0, 0xFFFF);
                break;
            }
            return 0;
        }
        opt = opt->next;
    }

    return -1;
}

void perf_long_opt_usage(void)
{
    fprintf(stderr, "Usage: %s ... -O <name>[=<value>] ...\n\nAvailable long options:\n", progname);
    long_opt_t* opt = longopts;
    while (opt) {
        if (opt->type == perf_opt_boolean) {
            fprintf(stderr, "  %s: %s", opt->name, opt->help);
        } else {
            fprintf(stderr, "  %s=<%s>: %s", opt->name, opt->desc ? opt->desc : "val", opt->help);
        }
        if (opt->defval) {
            fprintf(stderr, " (default: %s)", opt->defval);
        }
        fprintf(stderr, "\n");

        opt = opt->next;
    }
}

void perf_opt_parse(int argc, char** argv)
{
    int          c;
    opt_t*       opt;
    unsigned int i;

    perf_opt_add('h', perf_opt_boolean, NULL, "print this help", NULL, NULL);
    perf_opt_add('H', perf_opt_boolean, NULL, "print long options help", NULL, NULL);
    perf_opt_add('O', perf_opt_string, NULL, "set long options: <name>=<value>", NULL, NULL);

    while ((c = getopt(argc, argv, optstr)) != -1) {
        for (i = 0; i < nopts; i++) {
            if (opts[i].c == c)
                break;
        }
        if (i == nopts) {
            perf_opt_usage();
            exit(1);
        }
        if (c == 'h') {
            perf_opt_usage();
            exit(0);
        }
        if (c == 'H') {
            perf_long_opt_usage();
            exit(0);
        }
        if (c == 'O') {
            if (perf_opt_long_parse(optarg)) {
                fprintf(stderr, "invalid long option: %s\n", optarg);
                perf_opt_usage();
                exit(1);
            }
            continue;
        }
        opt = &opts[i];
        switch (opt->type) {
        case perf_opt_string:
            *opt->u.stringp = optarg;
            break;
        case perf_opt_boolean:
            *opt->u.boolp = true;
            break;
        case perf_opt_uint:
            *opt->u.uintp = parse_uint(opt->desc, optarg,
                1, 0xFFFFFFFF);
            break;
        case perf_opt_zpint:
            *opt->u.uintp = parse_uint(opt->desc, optarg,
                0, 0xFFFFFFFF);
            break;
        case perf_opt_timeval:
            *opt->u.uint64p = parse_timeval(opt->desc, optarg);
            break;
        case perf_opt_double:
            *opt->u.doublep = parse_double(opt->desc, optarg);
            break;
        case perf_opt_port:
            *opt->u.portp = parse_uint(opt->desc, optarg,
                0, 0xFFFF);
            break;
        }
    }
    if (optind != argc) {
        fprintf(stderr, "unexpected argument %s\n", argv[optind]);
        perf_opt_usage();
        exit(1);
    }
}

perf_suppress_t perf_opt_parse_suppress(const char* val)
{
    perf_suppress_t s = { false, false, false, false };

    while (val && *val) {
        const char* next = strchr(val, ',');
        int         len;
        if (next) {
            len = next - val;
            next += 1;
        } else {
            len  = strlen(val);
            next = 0;
        }

        if (!strncmp(val, "timeouts", len)) {
            s.timeouts = true;
        } else if (!strncmp(val, "congestion", len)) {
            s.congestion = true;
        } else if (!strncmp(val, "sendfailed", len)) {
            s.sendfailed = true;
        } else if (!strncmp(val, "sockready", len)) {
            s.sockready = true;
        } else if (!strncmp(val, "unexpected", len)) {
            s.unexpected = true;
        } else {
            fprintf(stderr, "unknown message type to suppress: %.*s\n", len, val);
            perf_opt_usage();
            exit(1);
        }

        val = next;
    }

    return s;
}
