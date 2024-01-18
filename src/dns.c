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

#include "dns.h"

#include "log.h"
#include "opt.h"
#include "qtype.h"

#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#ifdef HAVE_LDNS
#include <ldns/ldns.h>
#endif

#define WHITESPACE " \t\n"

#define MAX_RDATA_LENGTH 65535
#define EDNSLEN 11

const char* perf_dns_rcode_strings[] = {
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN",
    "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
    "NXRRSET", "NOTAUTH", "NOTZONE", "rcode11",
    "rcode12", "rcode13", "rcode14", "rcode15"
};

perf_result_t perf_dname_fromstring(const char* str, size_t len, perf_buffer_t* target)
{
    size_t      label_len, at;
    ssize_t     max      = 255;
    const char* orig_str = str;
    bool        is_quoted;

    if (perf_buffer_availablelength(target) < len) {
        return PERF_R_NOSPACE;
    }

    while (len) {
        is_quoted = false;
        for (label_len = 0, at = 0; at < len;) {
            if (*(str + at) == '\\') {
                is_quoted = true;
                at++;
                if (at >= len)
                    return PERF_R_FAILURE;
                if (*(str + at) >= '0' && *(str + at) <= '9') {
                    at++;
                    if (at >= len)
                        return PERF_R_FAILURE;
                    if (*(str + at) < '0' || *(str + at) > '9')
                        return PERF_R_FAILURE;
                    at++;
                    if (at >= len)
                        return PERF_R_FAILURE;
                    if (*(str + at) < '0' || *(str + at) > '9')
                        return PERF_R_FAILURE;
                }
            } else if (*(str + at) == '.') {
                break;
            }
            label_len++;
            at++;
        }
        if (!label_len) {
            // Just a dot
            if (len > 1) {
                // a dot but with labels after it
                return PERF_R_FAILURE;
            } else if (str != orig_str) {
                // a dot but with labels before it
                return PERF_R_FAILURE;
            }
            perf_buffer_putuint8(target, 0);
            break;
        }
        if (label_len > 63) {
            return PERF_R_FAILURE;
        }
        max -= label_len + 1;
        if (max < 0) {
            return PERF_R_FAILURE;
        }
        perf_buffer_putuint8(target, label_len);
        if (is_quoted) {
            for (at = 0; at < len; at++) {
                if (*(str + at) == '\\') {
                    at++;
                    if (*(str + at) >= '0' && *(str + at) <= '9') {
                        char b[4];
                        long v;
                        memcpy(b, str + at, 3);
                        at += 2;
                        b[3] = 0;
                        v    = strtol(b, 0, 7);
                        if (v < 0 || v > 255)
                            return PERF_R_FAILURE;
                        perf_buffer_putuint8(target, (uint8_t)v);
                        continue;
                    }
                } else if (*(str + at) == '.') {
                    break;
                }
                perf_buffer_putmem(target, str + at, 1);
            }
            str += at;
            len -= at;
        } else {
            perf_buffer_putmem(target, str, label_len);
            str += label_len;
            len -= label_len;
        }
        if (len < 2) {
            // Last label/dot
            perf_buffer_putuint8(target, 0);
            break;
        }
        // advance past dot
        str++;
        len--;
    }

    return PERF_R_SUCCESS;
}

perf_result_t perf_qtype_fromstring(const char* str, size_t len, perf_buffer_t* target)
{
    const perf_qtype_t* q = qtype_table;

    if (len > 4 && !strncasecmp(str, "TYPE", 4)) {
        char*             endptr = 0;
        unsigned long int u      = strtoul(str + 4, &endptr, 10);
        if (endptr != str + len || u == ULONG_MAX || u > 65535) {
            return PERF_R_FAILURE;
        }

        perf_buffer_putuint16(target, u);
        return PERF_R_SUCCESS;
    }

    while (q->type) {
        if (!strncasecmp(q->type, str, len)) {
            perf_buffer_putuint16(target, q->value);
            return PERF_R_SUCCESS;
        }
        q++;
    }

    return PERF_R_FAILURE;
}

static perf_result_t build_query(const perf_region_t* line, perf_buffer_t* msg)
{
    char *        domain_str, *qtype_str;
    size_t        domain_len, qtype_len;
    perf_result_t result;

    domain_str = line->base;
    domain_len = strcspn(line->base, WHITESPACE);

    if (!domain_len) {
        perf_log_warning("invalid query input format: %s", (char*)line->base);
        return PERF_R_FAILURE;
    }

    qtype_str = line->base + domain_len;
    while (isspace(*qtype_str))
        qtype_str++;
    qtype_len = strcspn(qtype_str, WHITESPACE);

    /* Create the question section */
    result = perf_dname_fromstring(domain_str, domain_len, msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid domain name (or out of space): %.*s", (int)domain_len, domain_str);
        return result;
    }

    if (!qtype_len) {
        perf_log_warning("invalid query input format: %s", (char*)line->base);
        return PERF_R_FAILURE;
    }

    result = perf_qtype_fromstring(qtype_str, qtype_len, msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid qtype: %.*s", (int)qtype_len, qtype_str);
        return result;
    }

    perf_buffer_putuint16(msg, 1); // class IN

    return PERF_R_SUCCESS;
}

#ifdef HAVE_LDNS
static bool token_equals(const perf_region_t* token, const char* str)
{
    return (strlen(str) == token->length && strncasecmp(str, token->base, token->length) == 0);
}

/*
 * Reads one line containing an individual update for a dynamic update message.
 */
static perf_result_t
read_update_line(char* str, const ldns_rdf* origin,
    bool want_ttl, bool need_type, bool want_rdata, bool need_rdata,
    ldns_rr** rr, const char** errstr)
{
    char   tmp[256], *str2;
    size_t len;

    while (isspace(*str & 0xff))
        str++;
    str2 = str;

    /*
     * Read the owner name
     */
    len = strcspn(str, WHITESPACE);
    if (len > sizeof(tmp) - 1) {
        *errstr = "domain name too large";
        return PERF_R_NOSPACE;
    }
    memcpy(tmp, str, len);
    tmp[len] = 0;

    ldns_rdf* owner;
    if (!(owner = ldns_dname_new_frm_str(tmp))) {
        *errstr = "invalid name or out of memory";
        return PERF_R_FAILURE;
    }
    ldns_rr_set_owner(*rr, owner);
    if (!ldns_dname_str_absolute(tmp) && origin) {
        if (ldns_dname_cat(ldns_rr_owner(*rr), origin) != LDNS_STATUS_OK) {
            return PERF_R_FAILURE;
        }
    }

    str += len;
    while (isspace(*str & 0xff))
        str++;

    /*
     * Read the ttl
     */
    if (want_ttl) {
        len = strcspn(str, WHITESPACE);
        if (len > sizeof(tmp) - 1) {
            *errstr = "TTL string too large";
            return PERF_R_NOSPACE;
        }
        memcpy(tmp, str, len);
        tmp[len] = 0;

        char*             endptr = 0;
        unsigned long int u      = strtoul(tmp, &endptr, 10);
        if (*endptr || u == ULONG_MAX) {
            *errstr = "TTL invalid";
            return PERF_R_INVALIDUPDATE;
        }

        ldns_rr_set_ttl(*rr, u);

        str += len;
        while (isspace(*str & 0xff))
            str++;
    }

    /*
     * Read the type
     */
    len = strcspn(str, WHITESPACE);
    if (!len) {
        if (!need_type)
            return PERF_R_SUCCESS;

        *errstr = "TYPE required";
        return PERF_R_INVALIDUPDATE;
    }
    if (len > sizeof(tmp) - 1) {
        *errstr = "TYPE string too large";
        return PERF_R_NOSPACE;
    }
    memcpy(tmp, str, len);
    tmp[len] = 0;

    ldns_rr_type type = ldns_get_rr_type_by_name(tmp);
    if (!type) {
        *errstr = "TYPE invalid";
        return PERF_R_INVALIDUPDATE;
    }
    ldns_rr_set_type(*rr, type);

    str += len;
    while (isspace(*str & 0xff))
        str++;

    if (!want_rdata)
        return PERF_R_SUCCESS;

    /*
     * Read the rdata
     */
    if (*str == 0) {
        if (!need_rdata)
            return PERF_R_SUCCESS;

        *errstr = "RDATA required";
        return PERF_R_INVALIDUPDATE;
    }

    // Need to recreate ldns_rr because there is no new_frm_str function to
    // correctly parse RDATA (quotes etc) for a RDF
    ldns_rr* rr2 = 0;
    if (ldns_rr_new_frm_str(&rr2, str2, 0, origin, 0) != LDNS_STATUS_OK) {
        *errstr = "invalid RDATA or out of memory";
        return PERF_R_INVALIDUPDATE;
    }

    // Force set TTL since if its missing in the input it will get the default
    // 3600 and not 0 as it should
    ldns_rr_set_ttl(rr2, ldns_rr_ttl(*rr));

    ldns_rr_free(*rr);
    *rr = rr2;

    return PERF_R_SUCCESS;
}

static void compression_free(ldns_rbnode_t* node, void* arg)
{
    (void)arg;
    ldns_rdf_deep_free((ldns_rdf*)node->key);
    LDNS_FREE(node);
}

/*
 * Reads a complete dynamic update message and sends it.
 */
static perf_result_t build_update(const perf_region_t* record, perf_buffer_t* msg)
{
    perf_region_t input, token;
    char *        msgbase, *str;
    bool          is_update;
    int           updates = 0;
    int           prereqs = 0;
    perf_result_t result  = PERF_R_FAILURE;
    ldns_rdf*     origin  = 0;
    ldns_rr*      rr      = 0;
    ldns_buffer*  lmsg    = 0;
    ldns_rbtree_t compression;
    const char*   errstr;

    input   = *record;
    msgbase = perf_buffer_base(msg);
    ldns_rbtree_init(&compression, ldns_dname_compare_v);

    // Fill LDNS buffer with current message (DNS headers)
    if (!(lmsg = ldns_buffer_new(perf_buffer_length(msg)))) {
        perf_log_fatal("unable to create LDNS buffer for DNS message");
        goto done; // for scan-build / sonarcloud
    }
    ldns_buffer_write(lmsg, perf_buffer_base(msg), perf_buffer_usedlength(msg));

    if (!(origin = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, input.base))) {
        perf_log_warning("Unable to parse domain name %s", (char*)input.base);
        goto done;
    }
    if (ldns_dname2buffer_wire_compress(lmsg, origin, &compression) != LDNS_STATUS_OK) {
        perf_log_warning("Unable to write domain name %s to wire format", (char*)input.base);
        goto done;
    }

    ldns_buffer_write_u16(lmsg, 6); // SOA
    ldns_buffer_write_u16(lmsg, 1); // IN

    while (true) {
        input.base += strlen(input.base) + 1;
        if (input.base >= record->base + record->length) {
            perf_log_warning("incomplete update: %s", (char*)record->base);
            result = PERF_R_FAILURE;
            goto done;
        }

        is_update    = false;
        token.base   = input.base;
        token.length = strcspn(token.base, WHITESPACE);
        str          = input.base + token.length;
        errstr       = 0;
        if (token_equals(&token, "send")) {
            break;
        }

        rr = ldns_rr_new();
        ldns_rr_set_ttl(rr, 0);
        ldns_rr_set_type(rr, LDNS_RR_TYPE_ANY);
        ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);

        if (token_equals(&token, "add")) {
            result = read_update_line(str, origin, true, true, true, true, &rr, &errstr);
            ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
            is_update = true;
        } else if (token_equals(&token, "delete")) {
            result = read_update_line(str, origin, false, false, true, false, &rr, &errstr);
            if (ldns_rr_rd_count(rr)) {
                ldns_rr_set_class(rr, LDNS_RR_CLASS_NONE);
            } else {
                ldns_rr_set_class(rr, LDNS_RR_CLASS_ANY);
            }
            is_update = true;
        } else if (token_equals(&token, "require")) {
            result = read_update_line(str, origin, false, false, true, false, &rr, &errstr);
            if (ldns_rr_rd_count(rr)) {
                ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
            } else {
                ldns_rr_set_class(rr, LDNS_RR_CLASS_ANY);
            }
            is_update = false;
        } else if (token_equals(&token, "prohibit")) {
            result = read_update_line(str, origin, false, false, false, false, &rr, &errstr);
            ldns_rr_set_class(rr, LDNS_RR_CLASS_NONE);
            is_update = false;
        } else {
            perf_log_warning("invalid update command: %s", (char*)input.base);
            result = PERF_R_FAILURE;
        }

        if (result != PERF_R_SUCCESS) {
            if (errstr) {
                perf_log_warning("invalid update command, %s: %s", errstr, (char*)input.base);
            } else if (result == PERF_R_INVALIDUPDATE) {
                perf_log_warning("invalid update command: %s", (char*)input.base);
            } else {
                perf_log_warning("error processing update command: %s", (char*)input.base);
            }
            ldns_rr_free(rr);
            goto done;
        }

        if (!is_update && updates > 0) {
            perf_log_warning("prereqs must precede updates");
            result = PERF_R_FAILURE;
            ldns_rr_free(rr);
            goto done;
        }

        if (ldns_rr2buffer_wire_compress(lmsg, rr, LDNS_SECTION_ANSWER, &compression) != LDNS_STATUS_OK) {
            perf_log_warning("Unable to write update message to wire format");
            ldns_rr_free(rr);
            goto done;
        }
        ldns_rr_free(rr);

        if (is_update)
            updates++;
        else
            prereqs++;
    }

    if (ldns_buffer_position(lmsg) - perf_buffer_usedlength(msg) > perf_buffer_availablelength(msg)) {
        perf_log_warning("out of space in message buffer");
        result = PERF_R_NOSPACE;
        goto done;
    }
    uint8_t* p = ldns_buffer_begin(lmsg) + perf_buffer_usedlength(msg);
    perf_buffer_putmem(msg, p, ldns_buffer_position(lmsg) - perf_buffer_usedlength(msg));

    msgbase[7] = prereqs; /* ANCOUNT = number of prereqs */
    msgbase[9] = updates; /* AUCOUNT = number of updates */

    result = PERF_R_SUCCESS;

done:
    ldns_buffer_free(lmsg);
    ldns_rdf_deep_free(origin);
    ldns_traverse_postorder(&compression, compression_free, 0);

    return result;
}
#endif

perf_result_t perf_dns_buildrequest(const perf_region_t* record, uint16_t qid,
    bool edns, bool dnssec, bool is_update,
    perf_tsigkey_t* tsigkey, perf_ednsoption_t* edns_option,
    perf_buffer_t* msg)
{
    unsigned int  flags;
    perf_result_t result;

    if (is_update)
        flags = 5 << 11; // opcode UPDATE
    else
        flags = 0x0100U; // flag RD

    /* Create the DNS packet header */
    perf_buffer_putuint16(msg, qid);
    perf_buffer_putuint16(msg, flags); /* flags */
    perf_buffer_putuint16(msg, 1); /* qdcount */
    perf_buffer_putuint16(msg, 0); /* ancount */
    perf_buffer_putuint16(msg, 0); /* aucount */
    perf_buffer_putuint16(msg, 0); /* arcount */

    if (is_update) {
#ifdef HAVE_LDNS
        result = build_update(record, msg);
#else
        result = PERF_R_FAILURE;
#endif
    } else {
        result = build_query(record, msg);
    }

    if (result == PERF_R_SUCCESS && edns) {
        result = perf_add_edns(msg, dnssec, edns_option);
    }

    if (result == PERF_R_SUCCESS && tsigkey) {
        result = perf_add_tsig(msg, tsigkey);
    }

    return result;
}
