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

#define _STATIC_DIGEST_BUFSIZE 128

#define WHITESPACE " \t\n"

#define MAX_RDATA_LENGTH 65535
#define EDNSLEN 11

const char* perf_dns_rcode_strings[] = {
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN",
    "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
    "NXRRSET", "NOTAUTH", "NOTZONE", "rcode11",
    "rcode12", "rcode13", "rcode14", "rcode15"
};

#define TSIG_HMACMD5_NAME "\010hmac-md5\007sig-alg\003reg\003int"
#define TSIG_HMACSHA1_NAME "\011hmac-sha1"
#define TSIG_HMACSHA224_NAME "\013hmac-sha224"
#define TSIG_HMACSHA256_NAME "\013hmac-sha256"
#define TSIG_HMACSHA384_NAME "\013hmac-sha384"
#define TSIG_HMACSHA512_NAME "\013hmac-sha512"

typedef enum {
    TSIG_HMACMD5,
    TSIG_HMACSHA1,
    TSIG_HMACSHA224,
    TSIG_HMACSHA256,
    TSIG_HMACSHA384,
    TSIG_HMACSHA512
} hmac_type_t;

typedef union {
    // isc_hmacmd5_t hmacmd5;
    // isc_hmacsha1_t   hmacsha1;
    // isc_hmacsha224_t hmacsha224;
    // isc_hmacsha256_t hmacsha256;
    // isc_hmacsha384_t hmacsha384;
    // isc_hmacsha512_t hmacsha512;
    int dummy;
} hmac_ctx_t;

struct perf_dnstsigkey {
    // isc_constregion_t alg;
    hmac_type_t  hmactype;
    unsigned int digestlen;
    // dns_fixedname_t   fname;
    // dns_name_t*       name;
    unsigned char secretdata[256];
    perf_buffer_t secret;
};

struct perf_dnsednsoption {
    perf_buffer_t buffer;
    char          data[];
};

struct perf_dnsctx {
    // isc_mem_t*     mctx;
    // dns_compress_t compress;
    // isc_lex_t*     lexer;
    int dummy;
};

perf_dnsctx_t* perf_dns_createctx(bool updates)
{
    // isc_mem_t*     mctx;
    // perf_dnsctx_t* ctx;
    // perf_result_t  result;

    if (!updates)
        return 0;

    //     mctx = NULL;
    // #ifdef HAVE_ISC_MEM_CREATE_RESULT
    //     result = isc_mem_create(0, 0, &mctx);
    //     if (result != ISC_R_SUCCESS)
    //         perf_log_fatal("creating memory context: %s",
    //             perf_result_totext(result));
    // #else
    //     isc_mem_create(&mctx);
    // #endif
    //
    //     ctx = isc_mem_get(mctx, sizeof(*ctx));
    //     if (ctx == NULL) {
    //         perf_log_fatal("out of memory");
    //         return 0; // fix clang scan-build
    //     }
    //
    //     memset(ctx, 0, sizeof(*ctx));
    //     ctx->mctx = mctx;
    //
    //     result = dns_compress_init(&ctx->compress, 0, ctx->mctx);
    //     if (result != ISC_R_SUCCESS) {
    //         perf_log_fatal("creating compression context: %s",
    //             perf_result_totext(result));
    //     }
    //     dns_compress_setmethods(&ctx->compress, DNS_COMPRESS_GLOBAL14);
    //
    //     result = isc_lex_create(ctx->mctx, 1024, &ctx->lexer);
    //     if (result != ISC_R_SUCCESS) {
    //         perf_log_fatal("creating lexer: %s", perf_result_totext(result));
    //     }
    //
    //     return (ctx);
    return 0;
}

void perf_dns_destroyctx(perf_dnsctx_t** ctxp)
{
    // perf_dnsctx_t* ctx;
    // isc_mem_t*     mctx;

    assert(ctxp);
    *ctxp = 0;

    // if (ctx == NULL)
    //     return;
    //
    // mctx = ctx->mctx;
    // isc_lex_destroy(&ctx->lexer);
    // dns_compress_invalidate(&ctx->compress);
    // isc_mem_put(mctx, ctx, sizeof(*ctx));
    // isc_mem_destroy(&mctx);
}

static perf_result_t name_fromstring(const char* str, size_t len, perf_buffer_t* target)
{
    size_t label_len;

    if (perf_buffer_availablelength(target) < len) {
        return PERF_R_NOSPACE;
    }

    while (len) {
        for (label_len = 0; label_len < len; label_len++) {
            if (*(str + label_len) == '.') {
                break;
            }
        }
        if (!label_len) {
            // Just a dot
            perf_buffer_putuint8(target, 0);
            break;
        }
        if (label_len > 63) {
            return PERF_R_FAILURE; // TODO: PERF_R_INVALIDNAME
        }
        perf_buffer_putuint8(target, label_len);
        perf_buffer_putmem(target, str, label_len);
        str += label_len;
        len -= label_len;
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

static perf_result_t qtype_fromstring(const char* str, size_t len, perf_buffer_t* target)
{
    const perf_qtype_t* q = qtype_table;

    while (q->type) {
        if (!strncasecmp(q->type, str, len)) {
            perf_buffer_putuint16(target, q->value);
            return PERF_R_SUCCESS;
        }
        q++;
    }

    return PERF_R_FAILURE;
}

#define SET_KEY(key, type)                 \
    do {                                   \
        (key)->hmactype = TSIG_HMAC##type; \
    } while (0)
// (key)->alg.base   = TSIG_HMAC##type##_NAME;
// (key)->alg.length = sizeof(TSIG_HMAC##type##_NAME);
// (key)->digestlen  = ISC_##type##_DIGESTLENGTH;

perf_dnstsigkey_t* perf_dns_parsetsigkey(const char* arg)
{
    perf_dnstsigkey_t* tsigkey;
    const char *       sep1, *sep2, *alg, *name, *secret;
    int                alglen, namelen;
    // perf_result_t      result;

    tsigkey = calloc(1, sizeof(*tsigkey));
    if (!tsigkey) {
        perf_log_fatal("out of memory");
        return 0; // fix clang scan-build
    }

    sep1 = strchr(arg, ':');
    if (sep1 == NULL) {
        perf_log_warning("invalid TSIG [alg:]name:secret");
        perf_opt_usage();
        exit(1);
    }

    sep2 = strchr(sep1 + 1, ':');
    if (sep2 == NULL) {
        /* name:key */
        alg     = NULL;
        alglen  = 0;
        name    = arg;
        namelen = sep1 - arg;
        secret  = sep1 + 1;
    } else {
        /* [alg:]name:secret */
        alg     = arg;
        alglen  = sep1 - arg;
        name    = sep1 + 1;
        namelen = sep2 - sep1 - 1;
        secret  = sep2 + 1;
    }

    /* Algorithm */

    if (alg == NULL || strncasecmp(alg, "hmac-md5:", 9) == 0) {
        SET_KEY(tsigkey, MD5);
    } else if (strncasecmp(alg, "hmac-sha1:", 10) == 0) {
        SET_KEY(tsigkey, SHA1);
    } else if (strncasecmp(alg, "hmac-sha224:", 12) == 0) {
        SET_KEY(tsigkey, SHA224);
    } else if (strncasecmp(alg, "hmac-sha256:", 12) == 0) {
        SET_KEY(tsigkey, SHA256);
    } else if (strncasecmp(alg, "hmac-sha384:", 12) == 0) {
        SET_KEY(tsigkey, SHA384);
    } else if (strncasecmp(alg, "hmac-sha512:", 12) == 0) {
        SET_KEY(tsigkey, SHA512);
    } else {
        perf_log_warning("invalid TSIG algorithm %.*s", alglen, alg);
        perf_opt_usage();
        exit(1);
    }

    if (tsigkey->digestlen > _STATIC_DIGEST_BUFSIZE) {
        perf_log_fatal("unable to setup TSIG algorithm %.*s, digest buffer too small, please report to %s", alglen, alg, PACKAGE_BUGREPORT);
    }

    /* Name */

    (void)name;
    (void)namelen;
    (void)secret;
    perf_log_warning("TSIG option disabled");
    exit(1);

    // #ifdef dns_fixedname_init
    //     dns_fixedname_init(&tsigkey->fname);
    //     tsigkey->name = dns_fixedname_name(&tsigkey->fname);
    // #else
    //     tsigkey->name = dns_fixedname_initname(&tsigkey->fname);
    // #endif
    //     result = name_fromstring(tsigkey->name, dns_rootname, name, namelen,
    //         NULL, "TSIG key");
    // if (result != ISC_R_SUCCESS) {
    //     perf_opt_usage();
    //     exit(1);
    // }
    // (void)dns_name_downcase(tsigkey->name, tsigkey->name, NULL);

    /* Secret */

    perf_buffer_init(&tsigkey->secret, tsigkey->secretdata,
        sizeof(tsigkey->secretdata));
    // result = isc_base64_decodestring(secret, &tsigkey->secret);
    // if (result != ISC_R_SUCCESS) {
    //     perf_log_warning("invalid TSIG secret '%s'", secret);
    //     perf_opt_usage();
    //     exit(1);
    // }

    return tsigkey;
}

void perf_dns_destroytsigkey(perf_dnstsigkey_t** tsigkeyp)
{
    assert(tsigkeyp);
    assert(*tsigkeyp);

    free(*tsigkeyp);
    *tsigkeyp = 0;
}

perf_dnsednsoption_t* perf_dns_parseednsoption(const char* arg)
{
    char *                copy, *sep, *value, *endptr, hex[3];
    perf_dnsednsoption_t* option;
    size_t                data_len;
    unsigned long int     u;
    perf_buffer_t         save;

    copy = strdup(arg);
    if (!copy) {
        perf_log_fatal("out of memory");
        return 0; // fix clang scan-build
    }

    sep = strchr(copy, ':');
    if (!sep) {
        perf_log_warning("invalid EDNS Option, must be code:value");
        perf_opt_usage();
        exit(1);
    }
    *sep  = '\0';
    value = sep + 1;

    data_len = strlen(value);
    if (!data_len) {
        perf_log_warning("invalid EDNS Option, value is empty");
        perf_opt_usage();
        exit(1);
    }
    if (data_len & 1) {
        perf_log_warning("invalid EDNS Option, value must hex string (even number of characters)");
        perf_opt_usage();
        exit(1);
    }
    data_len /= 2;
    data_len += 4; // code, len, data...

    option = calloc(1, sizeof(perf_dnsednsoption_t) + data_len);
    if (!option) {
        perf_log_fatal("out of memory");
        free(copy); // fix clang scan-build
        return 0; // fix clang scan-build
    }
    perf_buffer_init(&option->buffer, &option->data[0], data_len);

    endptr = 0;
    u      = strtoul(copy, &endptr, 10);
    if (*endptr || u == ULONG_MAX) {
        perf_log_warning("invalid EDNS Option code '%s'", copy);
        perf_opt_usage();
        exit(1);
    }
    perf_buffer_putuint16(&option->buffer, u & 0xffff);

    save = option->buffer;
    perf_buffer_add(&option->buffer, 2);
    hex[2] = 0;
    while (*value) {
        memcpy(hex, value, 2);
        endptr = 0;
        u      = strtoul(hex, &endptr, 16);
        if (*endptr || u == ULONG_MAX) {
            perf_log_warning("invalid EDNS Option hex value '%.*s'", 2, value);
            perf_opt_usage();
            exit(1);
        }
        perf_buffer_putuint8(&option->buffer, u & 0xff);
        value += 2;
    }
    perf_buffer_putuint16(&save, perf_buffer_usedlength(&option->buffer) - 4);

    free(copy);

    return option;
}

void perf_dns_destroyednsoption(perf_dnsednsoption_t** optionp)
{
    assert(optionp);
    assert(*optionp);

    free(*optionp);
    *optionp = 0;
}

/*
 * Appends an OPT record to the packet.
 */
static perf_result_t add_edns(perf_buffer_t* packet, bool dnssec, perf_dnsednsoption_t* option)
{
    unsigned char* base;
    size_t         option_length = 0, total_length;

    if (option) {
        option_length = perf_buffer_usedlength(&option->buffer);
    }
    total_length = EDNSLEN + option_length;

    if (perf_buffer_availablelength(packet) < total_length) {
        perf_log_warning("failed to add OPT to query packet");
        return PERF_R_NOSPACE;
    }

    base = perf_buffer_base(packet);

    perf_buffer_putuint8(packet, 0); /* root name */
    perf_buffer_putuint16(packet, 41); /* OPT record */
    perf_buffer_putuint16(packet, MAX_EDNS_PACKET); /* class */
    perf_buffer_putuint8(packet, 0); /* xrcode */
    perf_buffer_putuint8(packet, 0); /* version */
    if (dnssec) {
        /* flags */
        perf_buffer_putuint16(packet, 0x8000);
    } else {
        perf_buffer_putuint16(packet, 0);
    }
    perf_buffer_putuint16(packet, option_length); /* rdlen */
    if (option) {
        perf_buffer_putmem(packet, perf_buffer_base(&option->buffer), option_length);
    }

    base[11]++; /* increment additional record count */

    return PERF_R_SUCCESS;
}

static void
hmac_init(perf_dnstsigkey_t* tsigkey, hmac_ctx_t* ctx)
{
    // unsigned char* secret;
    // unsigned int   length;
    //
    // secret = perf_buffer_base(&tsigkey->secret);
    // length = perf_buffer_usedlength(&tsigkey->secret);

    switch (tsigkey->hmactype) {
    case TSIG_HMACMD5:
        // isc_hmacmd5_init(&ctx->hmacmd5, secret, length);
        perf_log_fatal("no support for HMACMD5");
        break;
    case TSIG_HMACSHA1:
        // isc_hmacsha1_init(&ctx->hmacsha1, secret, length);
        perf_log_fatal("no support for HMACSHA1");
        break;
    case TSIG_HMACSHA224:
        // isc_hmacsha224_init(&ctx->hmacsha224, secret, length);
        perf_log_fatal("no support for HMACSHA224");
        break;
    case TSIG_HMACSHA256:
        // isc_hmacsha256_init(&ctx->hmacsha256, secret, length);
        perf_log_fatal("no support for HMACSHA256");
        break;
    case TSIG_HMACSHA384:
        // isc_hmacsha384_init(&ctx->hmacsha384, secret, length);
        perf_log_fatal("no support for HMACSHA384");
        break;
    case TSIG_HMACSHA512:
        // isc_hmacsha512_init(&ctx->hmacsha512, secret, length);
        perf_log_fatal("no support for HMACSHA512");
        break;
    }
}

static void
hmac_update(perf_dnstsigkey_t* tsigkey, hmac_ctx_t* ctx,
    unsigned char* data, unsigned int length)
{
    switch (tsigkey->hmactype) {
    case TSIG_HMACMD5:
        // isc_hmacmd5_update(&ctx->hmacmd5, data, length);
        perf_log_fatal("no support for HMACMD5");
        break;
    case TSIG_HMACSHA1:
        // isc_hmacsha1_update(&ctx->hmacsha1, data, length);
        perf_log_fatal("no support for HMACSHA1");
        break;
    case TSIG_HMACSHA224:
        // isc_hmacsha224_update(&ctx->hmacsha224, data, length);
        perf_log_fatal("no support for HMACSHA224");
        break;
    case TSIG_HMACSHA256:
        // isc_hmacsha256_update(&ctx->hmacsha256, data, length);
        perf_log_fatal("no support for HMACSHA256");
        break;
    case TSIG_HMACSHA384:
        // isc_hmacsha384_update(&ctx->hmacsha384, data, length);
        perf_log_fatal("no support for HMACSHA384");
        break;
    case TSIG_HMACSHA512:
        // isc_hmacsha512_update(&ctx->hmacsha512, data, length);
        perf_log_fatal("no support for HMACSHA512");
        break;
    }
}

static void
hmac_sign(perf_dnstsigkey_t* tsigkey, hmac_ctx_t* ctx, unsigned char* digest,
    unsigned int digestlen)
{
    switch (tsigkey->hmactype) {
    case TSIG_HMACMD5:
        // isc_hmacmd5_sign(&ctx->hmacmd5, digest);
        perf_log_fatal("no support for HMACMD5");
        break;
    case TSIG_HMACSHA1:
        // isc_hmacsha1_sign(&ctx->hmacsha1, digest, digestlen);
        perf_log_fatal("no support for HMACSHA1");
        break;
    case TSIG_HMACSHA224:
        // isc_hmacsha224_sign(&ctx->hmacsha224, digest, digestlen);
        perf_log_fatal("no support for HMACSHA224");
        break;
    case TSIG_HMACSHA256:
        // isc_hmacsha256_sign(&ctx->hmacsha256, digest, digestlen);
        perf_log_fatal("no support for HMACSHA256");
        break;
    case TSIG_HMACSHA384:
        // isc_hmacsha384_sign(&ctx->hmacsha384, digest, digestlen);
        perf_log_fatal("no support for HMACSHA384");
        break;
    case TSIG_HMACSHA512:
        // isc_hmacsha512_sign(&ctx->hmacsha512, digest, digestlen);
        perf_log_fatal("no support for HMACSHA512");
        break;
    }
}

/*
 * Appends a TSIG record to the packet.
 */
static perf_result_t
add_tsig(perf_buffer_t* packet, perf_dnstsigkey_t* tsigkey)
{
    // unsigned char* base;
    hmac_ctx_t hmac;
    // isc_region_t   name_r;
    // isc_region_t*  alg_r;
    // unsigned int   rdlen, totallen;
    unsigned char tmpdata[512];
    perf_buffer_t tmp;
    // uint32_t       now;
    unsigned char digest[_STATIC_DIGEST_BUFSIZE];

    hmac_init(tsigkey, &hmac);
    // now = time(NULL);
    // dns_name_toregion(tsigkey->name, &name_r);
    // alg_r = (isc_region_t*)&tsigkey->alg;
    //
    // /* Make sure everything will fit */
    // rdlen    = alg_r->length + 16 + tsigkey->digestlen;
    // totallen = name_r.length + 10 + rdlen;
    // if (totallen > perf_buffer_availablelength(packet)) {
    //     perf_log_warning("adding TSIG: out of space");
    //     return (PERF_R_NOSPACE);
    // }
    //
    // base = perf_buffer_base(packet);
    //
    // /* Digest the message */
    hmac_update(tsigkey, &hmac, perf_buffer_base(packet),
        perf_buffer_usedlength(packet));

    // /* Digest the TSIG record */
    perf_buffer_init(&tmp, tmpdata, sizeof tmpdata);
    // perf_buffer_copyregion(&tmp, &name_r); /* name */
    // perf_buffer_putuint16(&tmp, dns_rdataclass_any); /* class */
    // perf_buffer_putuint32(&tmp, 0); /* ttl */
    // perf_buffer_copyregion(&tmp, alg_r); /* alg */
    // perf_buffer_putuint16(&tmp, 0); /* time high */
    // perf_buffer_putuint32(&tmp, now); /* time low */
    // perf_buffer_putuint16(&tmp, 300); /* fudge */
    // perf_buffer_putuint16(&tmp, 0); /* error */
    // perf_buffer_putuint16(&tmp, 0); /* other length */
    hmac_update(tsigkey, &hmac, perf_buffer_base(&tmp),
        perf_buffer_usedlength(&tmp));
    hmac_sign(tsigkey, &hmac, digest, tsigkey->digestlen);

    // /* Add the TSIG record. */
    // perf_buffer_copyregion(packet, &name_r); /* name */
    // perf_buffer_putuint16(packet, dns_rdatatype_tsig); /* type */
    // perf_buffer_putuint16(packet, dns_rdataclass_any); /* class */
    // perf_buffer_putuint32(packet, 0); /* ttl */
    // perf_buffer_putuint16(packet, rdlen); /* rdlen */
    // perf_buffer_copyregion(packet, alg_r); /* alg */
    // perf_buffer_putuint16(packet, 0); /* time high */
    // perf_buffer_putuint32(packet, now); /* time low */
    // perf_buffer_putuint16(packet, 300); /* fudge */
    // perf_buffer_putuint16(packet, tsigkey->digestlen); /* digest len */
    // perf_buffer_putmem(packet, digest, tsigkey->digestlen); /* digest */
    // perf_buffer_putmem(packet, base, 2); /* orig ID */
    // perf_buffer_putuint16(packet, 0); /* error */
    // perf_buffer_putuint16(packet, 0); /* other len */
    //
    // base[11]++; /* increment record count */
    //
    // return (PERF_R_SUCCESS);
    return PERF_R_FAILURE;
}

static perf_result_t
build_query(const perf_region_t* line, perf_buffer_t* msg)
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
    result = name_fromstring(domain_str, domain_len, msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid domain name: %.*s", (int)domain_len, domain_str);
        return result;
    }

    if (!qtype_len) {
        perf_log_warning("invalid query input format: %s", (char*)line->base);
        return PERF_R_FAILURE;
    }

    result = qtype_fromstring(qtype_str, qtype_len, msg);
    if (result != PERF_R_SUCCESS) {
        perf_log_warning("invalid qtype: %.*s", (int)qtype_len, qtype_str);
        return result;
    }

    perf_buffer_putuint16(msg, 1); // class IN

    return PERF_R_SUCCESS;
}

// static bool
// token_equals(const isc_textregion_t* token, const char* str)
// {
//     return (strlen(str) == token->length && strncasecmp(str, token->base, token->length) == 0);
// }

/*
 * Reads one line containing an individual update for a dynamic update message.
 */
// static perf_result_t
// read_update_line(perf_dnsctx_t* ctx, const isc_textregion_t* line, char* str,
//     dns_name_t* zname, int want_ttl, int need_type,
//     int want_rdata, int need_rdata, dns_name_t* name,
//     uint32_t* ttlp, dns_rdatatype_t* typep,
//     dns_rdata_t* rdata, perf_buffer_t* rdatabuf)
// {
// char*                curr_str;
// unsigned int         curr_len;
// perf_buffer_t         buffer;
// isc_textregion_t     src;
// dns_rdatacallbacks_t callbacks;
// perf_result_t        result;
//
// while (isspace(*str & 0xff))
//     str++;
//
// /* Read the owner name */
// curr_str = str;
// curr_len = strcspn(curr_str, WHITESPACE);
// result   = name_fromstring(name, zname, curr_str, curr_len, NULL, "owner");
// if (result != ISC_R_SUCCESS)
//     return isc2perf_result(result);
// str += curr_len;
// while (isspace(*str & 0xff))
//     str++;
//
// /* Read the ttl */
// if (want_ttl) {
//     curr_str   = str;
//     curr_len   = strcspn(curr_str, WHITESPACE);
//     src.base   = curr_str;
//     src.length = curr_len;
//     result     = dns_ttl_fromtext(&src, ttlp);
//     if (result != ISC_R_SUCCESS) {
//         perf_log_warning("invalid ttl: %.*s", curr_len, curr_str);
//         return isc2perf_result(result);
//     }
//     str += curr_len;
//     while (isspace(*str & 0xff))
//         str++;
// }
//
// /* Read the type */
// curr_str = str;
// curr_len = strcspn(curr_str, WHITESPACE);
// if (curr_len == 0) {
//     if (!need_type)
//         return (PERF_R_SUCCESS);
//     perf_log_warning("invalid update command: %s", line->base);
//     return (PERF_R_SUCCESS);
// }
// src.base   = curr_str;
// src.length = curr_len;
// result     = dns_rdatatype_fromtext(typep, &src);
// if (result != ISC_R_SUCCESS) {
//     perf_log_warning("invalid type: %.*s", curr_len, curr_str);
//     return isc2perf_result(result);
// }
// str += curr_len;
// while (isspace(*str & 0xff))
//     str++;
//
// /* Read the rdata */
// if (!want_rdata)
//     return (PERF_R_SUCCESS);
//
// if (*str == 0) {
//     if (!need_rdata)
//         return (PERF_R_SUCCESS);
//     perf_log_warning("invalid update command: %s", line->base);
//     return (PERF_R_FAILURE);
// }
//
// perf_buffer_init(&buffer, str, strlen(str));
// perf_buffer_add(&buffer, strlen(str));
// result = isc_lex_openbuffer(ctx->lexer, &buffer);
// if (result != ISC_R_SUCCESS) {
//     perf_log_warning("setting up lexer: %s", perf_result_totext(result));
//     return isc2perf_result(result);
// }
// dns_rdatacallbacks_init_stdio(&callbacks);
// result = dns_rdata_fromtext(rdata, dns_rdataclass_in, *typep, ctx->lexer,
//     zname, 0, ctx->mctx, rdatabuf, &callbacks);
// (void)isc_lex_close(ctx->lexer);
// if (result != ISC_R_SUCCESS) {
//     perf_log_warning("parsing rdata: %s", str);
//     return isc2perf_result(result);
// }
//
// return (PERF_R_SUCCESS);
// }

/*
 * Reads a complete dynamic update message and sends it.
 */
static perf_result_t
build_update(perf_dnsctx_t* ctx, const perf_region_t* record,
    perf_buffer_t* msg)
{
    //     isc_textregion_t input;
    //     char*            msgbase;
    //     perf_buffer_t     rdlenbuf, rdatabuf;
    //     unsigned char    rdataarray[MAX_RDATA_LENGTH];
    //     isc_textregion_t token;
    //     char*            str;
    //     bool             is_update;
    //     int              updates = 0;
    //     int              prereqs = 0;
    //     dns_fixedname_t  fzname, foname;
    //     dns_name_t *     zname, *oname;
    //     uint32_t         ttl;
    //     dns_rdatatype_t  rdtype;
    //     dns_rdataclass_t rdclass;
    //     dns_rdata_t      rdata;
    //     uint16_t         rdlen;
    //     perf_result_t    result;
    //
    //     /* Reset compression context */
    //     dns_compress_rollback(&ctx->compress, 0);
    //
    //     input   = *record;
    //     msgbase = perf_buffer_base(msg);
    //
    // /* Initialize */
    // #ifdef dns_fixedname_init
    //     dns_fixedname_init(&foname);
    //     oname = dns_fixedname_name(&foname);
    // #else
    //     oname = dns_fixedname_initname(&foname);
    // #endif
    //
    // /* Parse zone name */
    // #ifdef dns_fixedname_init
    //     dns_fixedname_init(&fzname);
    //     zname = dns_fixedname_name(&fzname);
    // #else
    //     zname = dns_fixedname_initname(&fzname);
    // #endif
    //     result = name_fromstring(zname, dns_rootname,
    //         input.base, strlen(input.base),
    //         NULL, "zone");
    //     if (result != ISC_R_SUCCESS)
    //         goto done;
    //
    //     /* Render zone section */
    //     result = dns_name_towire(zname, &ctx->compress, msg);
    //     if (result != ISC_R_SUCCESS) {
    //         perf_log_warning("error rendering zone name: %s",
    //             perf_result_totext(result));
    //         goto done;
    //     }
    //     perf_buffer_putuint16(msg, dns_rdatatype_soa);
    //     perf_buffer_putuint16(msg, dns_rdataclass_in);
    //
    //     while (true) {
    //         input.base += strlen(input.base) + 1;
    //         if (input.base >= record->base + record->length) {
    //             perf_log_warning("warning: incomplete update");
    //             goto done;
    //         }
    //
    //         ttl    = 0;
    //         rdtype = dns_rdatatype_any;
    //         perf_buffer_init(&rdatabuf, rdataarray, sizeof(rdataarray));
    //         dns_rdata_init(&rdata);
    //         rdclass   = dns_rdataclass_in;
    //         is_update = false;
    //
    //         token.base   = input.base;
    //         token.length = strcspn(token.base, WHITESPACE);
    //         str          = input.base + token.length;
    //         if (token_equals(&token, "send")) {
    //             break;
    //         } else if (token_equals(&token, "add")) {
    //             result    = read_update_line(ctx, &input, str, zname,
    //                 true, true, true,
    //                 true, oname, &ttl, &rdtype,
    //                 &rdata, &rdatabuf);
    //             rdclass   = dns_rdataclass_in;
    //             is_update = true;
    //         } else if (token_equals(&token, "delete")) {
    //             result = read_update_line(ctx, &input, str, zname,
    //                 false, false, true,
    //                 false, oname, &ttl,
    //                 &rdtype, &rdata, &rdatabuf);
    //             if (perf_buffer_usedlength(&rdatabuf) > 0)
    //                 rdclass = dns_rdataclass_none;
    //             else
    //                 rdclass = dns_rdataclass_any;
    //             is_update = true;
    //         } else if (token_equals(&token, "require")) {
    //             result = read_update_line(ctx, &input, str, zname,
    //                 false, false, true,
    //                 false, oname, &ttl,
    //                 &rdtype, &rdata, &rdatabuf);
    //             if (perf_buffer_usedlength(&rdatabuf) > 0)
    //                 rdclass = dns_rdataclass_in;
    //             else
    //                 rdclass = dns_rdataclass_any;
    //             is_update = false;
    //         } else if (token_equals(&token, "prohibit")) {
    //             result    = read_update_line(ctx, &input, str, zname,
    //                 false, false, false,
    //                 false, oname, &ttl,
    //                 &rdtype, &rdata, &rdatabuf);
    //             rdclass   = dns_rdataclass_none;
    //             is_update = false;
    //         } else {
    //             perf_log_warning("invalid update command: %s", input.base);
    //             result = PERF_R_FAILURE;
    //         }
    //
    //         if (result != PERF_R_SUCCESS)
    //             goto done;
    //
    //         if (!is_update && updates > 0) {
    //             perf_log_warning("prereqs must precede updates");
    //             result = PERF_R_FAILURE;
    //             goto done;
    //         }
    //
    //         /* Render record */
    //         result = dns_name_towire(oname, &ctx->compress, msg);
    //         if (result != PERF_R_SUCCESS) {
    //             perf_log_warning("rendering record name: %s",
    //                 perf_result_totext(result));
    //             goto done;
    //         }
    //         if (perf_buffer_availablelength(msg) < 10) {
    //             perf_log_warning("out of space in message buffer");
    //             result = PERF_R_NOSPACE;
    //             goto done;
    //         }
    //
    //         perf_buffer_putuint16(msg, rdtype);
    //         perf_buffer_putuint16(msg, rdclass);
    //         perf_buffer_putuint32(msg, ttl);
    //         rdlenbuf = *msg;
    //         perf_buffer_putuint16(msg, 0); /* rdlen */
    //         rdlen = perf_buffer_usedlength(&rdatabuf);
    //         if (rdlen > 0) {
    //             result = dns_rdata_towire(&rdata, &ctx->compress, msg);
    //             if (result != ISC_R_SUCCESS) {
    //                 perf_log_warning("rendering rdata: %s",
    //                     perf_result_totext(result));
    //                 goto done;
    //             }
    //             rdlen = msg->used - rdlenbuf.used - 2;
    //             perf_buffer_putuint16(&rdlenbuf, rdlen);
    //         }
    //         if (is_update)
    //             updates++;
    //         else
    //             prereqs++;
    //     }
    //
    //     msgbase[7] = prereqs; /* ANCOUNT = number of prereqs */
    //     msgbase[9] = updates; /* AUCOUNT = number of updates */
    //
    //     result = PERF_R_SUCCESS;
    //
    // done:
    //     return result;
    return PERF_R_FAILURE;
}

perf_result_t
perf_dns_buildrequest(perf_dnsctx_t* ctx, const perf_region_t* record,
    uint16_t qid,
    bool edns, bool dnssec,
    perf_dnstsigkey_t* tsigkey, perf_dnsednsoption_t* option,
    perf_buffer_t* msg)
{
    unsigned int  flags;
    perf_result_t result;

    if (ctx != NULL)
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

    if (ctx != NULL) {
        result = build_update(ctx, record, msg);
    } else {
        result = build_query(record, msg);
    }
    if (result != PERF_R_SUCCESS)
        return (result);

    if (edns) {
        result = add_edns(msg, dnssec, option);
        if (result != PERF_R_SUCCESS)
            return (result);
    }

    if (tsigkey != NULL) {
        result = add_tsig(msg, tsigkey);
        if (result != PERF_R_SUCCESS)
            return (result);
    }

    return (PERF_R_SUCCESS);
}
