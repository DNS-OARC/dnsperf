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

#include "tsig.h"

#include "log.h"
#include "opt.h"
#include "dns.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/evp.h>
#include <time.h>

#define TSIG_HMACMD5_NAME "hmac-md5.sig-alg.reg.int"
#define TSIG_HMACSHA1_NAME "hmac-sha1"
#define TSIG_HMACSHA224_NAME "hmac-sha224"
#define TSIG_HMACSHA256_NAME "hmac-sha256"
#define TSIG_HMACSHA384_NAME "hmac-sha384"
#define TSIG_HMACSHA512_NAME "hmac-sha512"

static unsigned char* decode64(const void* base64, int* len)
{
    unsigned char* out;

    assert(base64);
    assert(len);
    assert(*len);

    out = calloc(1, *len);
    assert(out);

    int olen = *len;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_ENCODE_CTX evp;
    EVP_DecodeInit(&evp);
    if (EVP_DecodeUpdate(&evp, out, &olen, base64, *len)) {
        free(out);
        return 0;
    }
#else
    EVP_ENCODE_CTX* evp = EVP_ENCODE_CTX_new();
    if (!evp) {
        free(out);
        return 0;
    }
    EVP_DecodeInit(evp);
    if (EVP_DecodeUpdate(evp, out, &olen, base64, *len)) {
        free(out);
        EVP_ENCODE_CTX_free(evp);
        return 0;
    }
    EVP_ENCODE_CTX_free(evp);
#endif

    *len = olen;

    return out;
}

perf_tsigkey_t* perf_tsig_parsekey(const char* arg)
{
    perf_tsigkey_t* tsigkey;
    const char *    sep1, *sep2, *alg, *name, *secret;
    size_t          alglen, namelen, secretlen;
    int             keylen;
    const EVP_MD*   md = 0;

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

    if (!alg || !strncasecmp(alg, "hmac-md5:", 9)) {
        md              = EVP_md5();
        tsigkey->alg    = TSIG_HMACMD5_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACMD5_NAME) - 1;
    } else if (!strncasecmp(alg, "hmac-sha1:", 10)) {
        md              = EVP_sha1();
        tsigkey->alg    = TSIG_HMACSHA1_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACSHA1_NAME) - 1;
    } else if (!strncasecmp(alg, "hmac-sha224:", 12)) {
        md              = EVP_sha224();
        tsigkey->alg    = TSIG_HMACSHA224_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACSHA224_NAME) - 1;
    } else if (!strncasecmp(alg, "hmac-sha256:", 12)) {
        md              = EVP_sha256();
        tsigkey->alg    = TSIG_HMACSHA256_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACSHA256_NAME) - 1;
    } else if (!strncasecmp(alg, "hmac-sha384:", 12)) {
        md              = EVP_sha384();
        tsigkey->alg    = TSIG_HMACSHA384_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACSHA384_NAME) - 1;
    } else if (!strncasecmp(alg, "hmac-sha512:", 12)) {
        md              = EVP_sha512();
        tsigkey->alg    = TSIG_HMACSHA512_NAME;
        tsigkey->alglen = sizeof(TSIG_HMACSHA512_NAME) - 1;
    } else {
        perf_log_warning("invalid TSIG algorithm %.*s", (int)alglen, alg);
        perf_opt_usage();
        exit(1);
    }

    if (namelen > sizeof(tsigkey->name)) {
        perf_log_fatal("unable to setup TSIG, name too long");
        // fix clang scan-build / sonarcloud:
        free(tsigkey);
        return 0;
    }
    memcpy(tsigkey->name, name, namelen);
    tsigkey->namelen = namelen;
    for (namelen = 0; namelen < tsigkey->namelen; namelen++) {
        tsigkey->name[namelen] = tolower(tsigkey->name[namelen]);
    }

    /* Secret */

    secretlen = strlen(secret);
    if (!secretlen) {
        perf_log_warning("unable to setup TSIG, secret empty");
        perf_opt_usage();
        exit(1);
    }

    keylen             = secretlen;
    unsigned char* key = decode64(secret, &keylen);
    if (!key) {
        perf_log_fatal("unable to setup TSIG, invalid base64 secret");
    }

    /* Setup HMAC */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!(tsigkey->hmac = calloc(1, sizeof(*tsigkey->hmac)))) {
        perf_log_fatal("unable to setup TSIG, OpenSSL HMAC context failed to be created");
    }
    HMAC_CTX_init(tsigkey->hmac);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!(tsigkey->hmac = HMAC_CTX_new())) {
        perf_log_fatal("unable to setup TSIG, OpenSSL HMAC context failed to be created");
    }
#else
    if (!(tsigkey->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, 0, key, keylen))) {
        perf_log_fatal("unable to setup TSIG, OpenSSL EVP PKEY failed to be created");
    }
    if (!(tsigkey->mdctx = EVP_MD_CTX_create())) {
        perf_log_fatal("unable to setup TSIG, OpenSSL EVP MD context failed to be created");
    }
    if (!EVP_DigestSignInit(tsigkey->mdctx, 0, md, 0, tsigkey->pkey)) {
        perf_log_fatal("unable to setup TSIG, OpenSSL EVP DigestSign init failed");
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!HMAC_Init_ex(tsigkey->hmac, key, keylen, md, 0)) {
        perf_log_fatal("unable to setup TSIG, OpenSSL HMAC init failed");
    }
#endif

    free(key);

    return tsigkey;
}

void perf_tsig_destroykey(perf_tsigkey_t** tsigkeyp)
{
    assert(tsigkeyp);
    assert(*tsigkeyp);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup((*tsigkeyp)->hmac);
    free((*tsigkeyp)->hmac);
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX_free((*tsigkeyp)->hmac);
#else
    EVP_MD_CTX_free((*tsigkeyp)->mdctx);
    EVP_PKEY_free((*tsigkeyp)->pkey);
#endif

    free(*tsigkeyp);
    *tsigkeyp = 0;
}

/*
 * Appends a TSIG record to the packet.
 */
perf_result_t perf_add_tsig(perf_buffer_t* packet, perf_tsigkey_t* tsigkey)
{
    unsigned char* base;
    size_t         rdlen, totallen;
    unsigned char  tmpdata[512], md[EVP_MAX_MD_SIZE];
    perf_buffer_t  tmp;
    uint32_t       now;
    perf_result_t  result;

    now = time(NULL);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!HMAC_Init_ex(tsigkey->hmac, 0, 0, 0, 0)) {
        perf_log_fatal("adding TSIG: OpenSSL HMAC reinit failed");
    }
    if (!HMAC_Update(tsigkey->hmac, perf_buffer_base(packet), perf_buffer_usedlength(packet))) {
        perf_log_fatal("adding TSIG: OpenSSL HMAC update failed");
    }
#else
    if (!EVP_DigestSignInit(tsigkey->mdctx, 0, 0, 0, 0)) {
        perf_log_fatal("adding TSIG: OpenSSL EVP DigestSign reinit failed");
    }
    if (!EVP_DigestSignUpdate(tsigkey->mdctx, perf_buffer_base(packet), perf_buffer_usedlength(packet))) {
        perf_log_fatal("adding TSIG: OpenSSL EVP DigestSign update failed");
    }
#endif

    /* Digest the TSIG record */
    perf_buffer_init(&tmp, tmpdata, sizeof tmpdata);
    switch ((result = perf_dname_fromstring(tsigkey->name, tsigkey->namelen, &tmp))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space in digest record");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid owner name");
        return result;
    }
    perf_buffer_putuint16(&tmp, 255); /* class ANY */
    perf_buffer_putuint32(&tmp, 0); /* ttl */
    switch ((result = perf_dname_fromstring(tsigkey->alg, tsigkey->alglen, &tmp))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space in digest record");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid algorithm name");
        return result;
    }
    perf_buffer_putuint16(&tmp, 0); /* time high */
    perf_buffer_putuint32(&tmp, now); /* time low */
    perf_buffer_putuint16(&tmp, 300); /* fudge */
    perf_buffer_putuint16(&tmp, 0); /* error */
    perf_buffer_putuint16(&tmp, 0); /* other length */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    unsigned int mdlen = sizeof(md);
    if (!HMAC_Update(tsigkey->hmac, perf_buffer_base(&tmp), perf_buffer_usedlength(&tmp))) {
        perf_log_fatal("adding TSIG: OpenSSL HMAC update failed");
    }
    if (!HMAC_Final(tsigkey->hmac, md, &mdlen)) {
        perf_log_fatal("adding TSIG: OpenSSL HMAC final failed");
    }
#else
    size_t mdlen = sizeof(md);
    if (!EVP_DigestSignUpdate(tsigkey->mdctx, perf_buffer_base(&tmp), perf_buffer_usedlength(&tmp))) {
        perf_log_fatal("adding TSIG: OpenSSL EVP DigestSign update failed");
    }
    if (!EVP_DigestSignFinal(tsigkey->mdctx, md, &mdlen)) {
        perf_log_fatal("adding TSIG: OpenSSL EVP DigestSign final failed");
    }
#endif

    /* Make sure everything will fit */
    rdlen    = tsigkey->alglen + 18 + mdlen;
    totallen = tsigkey->namelen + 12 + rdlen;
    if (totallen > perf_buffer_availablelength(packet)) {
        perf_log_warning("adding TSIG: out of space");
        return PERF_R_NOSPACE;
    }

    base = perf_buffer_base(packet);

    /* Add the TSIG record. */
    switch ((result = perf_dname_fromstring(tsigkey->name, tsigkey->namelen, packet))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid owner name");
        return result;
    }
    perf_buffer_putuint16(packet, 250); /* type TSIG */
    perf_buffer_putuint16(packet, 255); /* class ANY */
    perf_buffer_putuint32(packet, 0); /* ttl */
    perf_buffer_putuint16(packet, rdlen); /* rdlen */
    switch ((result = perf_dname_fromstring(tsigkey->alg, tsigkey->alglen, packet))) {
    case PERF_R_SUCCESS:
        break;
    case PERF_R_NOSPACE:
        perf_log_warning("adding TSIG: out of space");
        return result;
    default:
        perf_log_warning("adding TSIG: invalid algorithm name");
        return result;
    }
    perf_buffer_putuint16(packet, 0); /* time high */
    perf_buffer_putuint32(packet, now); /* time low */
    perf_buffer_putuint16(packet, 300); /* fudge */
    perf_buffer_putuint16(packet, mdlen); /* digest len */
    perf_buffer_putmem(packet, md, mdlen); /* digest */
    perf_buffer_putmem(packet, base, 2); /* orig ID */
    perf_buffer_putuint16(packet, 0); /* error */
    perf_buffer_putuint16(packet, 0); /* other len */

    base[11]++; /* increment additional record count */

    return PERF_R_SUCCESS;
}
