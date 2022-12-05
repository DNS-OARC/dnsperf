/*
 * hg64 - 64-bit histograms
 *
 * Written by Tony Finch <dot@dotat.at> <fanf@isc.org>
 *
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hg64.h"

/* number of bins is same as number of bits in a value */
#define BINS 64

typedef atomic_uint_fast64_t counter;
typedef _Atomic(counter*)    bin_ptr;

struct hg64 {
    unsigned sigbits;
    bin_ptr  bin[BINS];
};

static inline counter*
get_bin(hg64* hg, unsigned b)
{
    /* key_to_new_counter() below has the matching store / release */
    return (atomic_load_explicit(&hg->bin[b], memory_order_acquire));
}

/*
 * when we only care about the histogram precision
 */
struct hg64p {
    unsigned sigbits;
};

#ifdef __has_attribute
#if __has_attribute(__transparent_union__)
#define TRANSPARENT __attribute__((__transparent_union__))
#endif
#endif

#ifdef TRANSPARENT

typedef union hg64u {
    hg64*               hg;
    const struct hg64p* hp;
} hg64u TRANSPARENT;

#define hg64p(hu) ((hu).hp)
#else

typedef void* hg64u;

#define hg64p(hu) ((const struct hg64p*)(hu))
#endif

/*
 * The bins arrays have a static size for simplicity, but that means We
 * waste a little extra space that could be saved by omitting the
 * exponents that land in the denormal number bin. The following macros
 * calculate (at run time) the exact number of keys when we need to do
 * accurate bounds checks.
 */
#define DENORMALS(hp) ((hp)->sigbits - 1)
#define EXPONENTS(hp) (BINS - DENORMALS(hp))
#define MANTISSAS(hp) (1 << (hp)->sigbits)
#define KEYS(hp) (EXPONENTS(hp) * MANTISSAS(hp))

#define BINSIZE(hp) MANTISSAS(hp)

/**********************************************************************/

#define OUTARG(ptr, val) (void)(((ptr) != NULL) && (bool)(*(ptr) = (val)))

/**********************************************************************/

hg64* hg64_create(unsigned sigbits)
{
    if (sigbits < 1 || 15 < sigbits) {
        return (NULL);
    }
    hg64* hg    = malloc(sizeof(*hg));
    hg->sigbits = sigbits;
    /*
     * it is probably portable to zero-initialize atomics but the
     * C standard says we shouldn't rely on it; but this loop
     * should optimize to memset() on most target systems
     */
    for (unsigned b = 0; b < BINS; b++) {
        atomic_init(&hg->bin[b], NULL);
    }
    return (hg);
}

void hg64_destroy(hg64* hg)
{
    for (unsigned b = 0; b < BINS; b++) {
        free(get_bin(hg, b));
    }
    *hg = (hg64) { 0 };
    free(hg);
}

/**********************************************************************/

static inline uint64_t
key_to_minval(hg64u hu, unsigned key)
{
    unsigned binsize  = BINSIZE(hg64p(hu));
    unsigned exponent = (key / binsize) - 1;
    uint64_t mantissa = (key % binsize) + binsize;
    return (key < binsize ? key : mantissa << exponent);
}

/*
 * don't shift by 64, and don't underflow exponent; instead,
 * reduce shift by 1 for each hazard and pre-shift UINT64_MAX
 */
static inline uint64_t
key_to_maxval(hg64u hu, unsigned key)
{
    unsigned binsize = BINSIZE(hg64p(hu));
    unsigned shift   = 63 - (key / binsize);
    uint64_t range   = UINT64_MAX / 4 >> shift;
    return (key_to_minval(hu, key) + range);
}

/*
 * This branchless conversion is due to Paul Khuong: see bin_down_of() in
 * https://pvk.ca/Blog/2015/06/27/linear-log-bucketing-fast-versatile-simple/
 */
static inline unsigned
value_to_key(hg64u hu, uint64_t value)
{
    /* fast path */
    const struct hg64p* hp = hg64p(hu);
    /* ensure that denormal numbers are all in the same bin */
    uint64_t binned = value | BINSIZE(hp);
    int      clz    = __builtin_clzll((unsigned long long)(binned));
    /* actually 1 less than the exponent except for denormals */
    unsigned exponent = 63 - hp->sigbits - clz;
    /* mantissa has leading bit set except for denormals */
    unsigned mantissa = value >> exponent;
    /* leading bit of mantissa adds one to exponent */
    return ((exponent << hp->sigbits) + mantissa);
}

static counter*
key_to_new_counter(hg64* hg, unsigned key)
{
    /* slow path */
    unsigned binsize = BINSIZE(hg);
    unsigned b       = key / binsize;
    unsigned c       = key % binsize;
    counter* old_bp  = NULL;
    counter* new_bp  = malloc(sizeof(counter) * binsize);
    /* see comment in hg64_create() above */
    for (unsigned i = 0; i < binsize; i++) {
        atomic_init(new_bp + i, 0);
    }
    bin_ptr* bpp = &hg->bin[b];
    if (atomic_compare_exchange_strong_explicit(bpp, &old_bp, new_bp,
            memory_order_acq_rel, memory_order_acquire)) {
        return (new_bp + c);
    } else {
        /* lost the race, so use the winner's counters */
        free(new_bp);
        return (old_bp + c);
    }
}

static inline counter*
key_to_counter(hg64* hg, unsigned key)
{
    /* fast path */
    unsigned binsize = BINSIZE(hg);
    unsigned b       = key / binsize;
    unsigned c       = key % binsize;
    counter* bp      = get_bin(hg, b);
    return (bp == NULL ? NULL : bp + c);
}

static inline uint64_t
get_key_count(hg64* hg, unsigned key)
{
    counter* ctr = key_to_counter(hg, key);
    return (ctr == NULL ? 0 : atomic_load_explicit(ctr, memory_order_relaxed));
}

static inline void
add_key_count(hg64* hg, unsigned key, uint64_t inc)
{
    if (inc == 0)
        return;
    counter* ctr = key_to_counter(hg, key);
    ctr          = ctr ? ctr : key_to_new_counter(hg, key);
    atomic_fetch_add_explicit(ctr, inc, memory_order_relaxed);
}

/**********************************************************************/

void hg64_inc(hg64* hg, uint64_t value)
{
    add_key_count(hg, value_to_key(hg, value), 1);
}

bool hg64_get(hg64* hg, unsigned key,
    uint64_t* pmin, uint64_t* pmax, uint64_t* pcount)
{
    if (key < KEYS(hg)) {
        OUTARG(pmin, key_to_minval(hg, key));
        OUTARG(pmax, key_to_maxval(hg, key));
        OUTARG(pcount, get_key_count(hg, key));
        return (true);
    } else {
        return (false);
    }
}

unsigned
hg64_next(hg64* hg, unsigned key)
{
    key++;
    while (key < KEYS(hg) && (key & (BINSIZE(hg) - 1)) == 0 && key_to_counter(hg, key) == NULL) {
        key += BINSIZE(hg);
    }
    return (key);
}

/*
 * https://fanf2.user.srcf.net/hermes/doc/antiforgery/stats.pdf
 */
void hg64_mean_variance(hg64* hg, double* pmean, double* pvar)
{
    double   pop   = 0.0;
    double   mean  = 0.0;
    double   sigma = 0.0;
    uint64_t min, max, count;
    for (unsigned key = 0;
         hg64_get(hg, key, &min, &max, &count);
         key = hg64_next(hg, key)) {
        double delta = (double)min / 2.0 + (double)max / 2.0 - mean;
        if (count != 0) { /* avoid division by zero */
            pop += count;
            mean += count * delta / pop;
            sigma += count * delta * (min + max - mean);
        }
    }
    OUTARG(pmean, mean);
    OUTARG(pvar, sigma / pop);
}

/**********************************************************************/

void hg64_merge(hg64* target, hg64* source)
{
    uint64_t count;
    for (unsigned skey = 0;
         hg64_get(source, skey, NULL, NULL, &count);
         skey = hg64_next(source, skey)) {
        uint64_t svmin = key_to_minval(source, skey);
        uint64_t svmax = key_to_maxval(source, skey);
        unsigned tkmin = value_to_key(target, svmin);
        unsigned tkmax = value_to_key(target, svmax);
        unsigned keys  = tkmax - tkmin + 1;
        /* is there a more cunning way to spread out the remainder? */
        uint64_t div = count / keys;
        uint64_t rem = count % keys;
        for (unsigned tkey = tkmin; tkey <= tkmax; tkey++) {
            uint64_t inc = div + (uint64_t)(tkey < rem);
            add_key_count(target, tkey, inc);
        }
    }
}

void hg64_diff(hg64* a, hg64* b, hg64* diff)
{
    assert((a->sigbits == b->sigbits) && (b->sigbits == diff->sigbits));
    uint64_t count_a = 0;
    uint64_t count_b = 0;
    for (unsigned key = 0;
         hg64_get(a, key, NULL, NULL, &count_a);
         key++) {
        hg64_get(b, key, NULL, NULL, &count_b);
        add_key_count(diff, key, count_a - count_b);
    }
}

unsigned hg64_min_key(hg64* hg)
{
    uint64_t pcount;
    for (unsigned key = 0;
         hg64_get(hg, key, NULL, NULL, &pcount);
         key = hg64_next(hg, key)) {
        if (pcount > 0)
            return key;
    }
    return 0;
}

unsigned hg64_max_key(hg64* hg)
{
    unsigned last_key = 0;
    uint64_t pcount;
    for (unsigned key = 0;
         hg64_get(hg, key, NULL, NULL, &pcount);
         key = hg64_next(hg, key)) {
        if (pcount > 0)
            last_key = key;
    }
    return last_key;
}
