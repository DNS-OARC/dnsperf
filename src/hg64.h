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

#ifndef HG64_H
#define HG64_H 1

typedef struct hg64 hg64;

/*
 * Allocate a new histogram. `sigbits` must be between 1 and 15
 * inclusive; it is the number of significant bits of each value
 * to use when mapping values to buckets.
 */
hg64* hg64_create(unsigned sigbits);

/*
 * Free the memory used by a histogram
 */
void hg64_destroy(hg64* hg);

/*
 * Add 1 to the value's bucket
 */
void hg64_inc(hg64* hg, uint64_t value);

/*
 * Get information about a bucket. This can be used as an iterator,
 * by initializing `key` to zero and incrementing by one or using
 * `hg64_next()` until `hg64_get()` returns `false`. The number of
 * iterations is a little less than `1 << (6 + sigbits)`.
 *
 * If `pmin` is non-NULL it is set to the bucket's minimum inclusive value.
 *
 * If `pmax` is non-NULL it is set to the bucket's maximum inclusive value.
 *
 * If `pcount` is non-NULL it is set to the bucket's counter, which
 * can be zero. (Empty buckets are included in the iterator.)
 */
bool hg64_get(hg64* hg, unsigned key,
    uint64_t* pmin, uint64_t* pmax, uint64_t* pcount);

/*
 * Skip to the next key, omitting groups of nonexistent buckets.
 */
unsigned hg64_next(hg64* hg, unsigned key);

/*
 * Get summary statistics about the histogram.
 *
 * If `pmean` is non-NULL it is set to the mean of the recorded data.
 *
 * If `pvar` is non-NULL it is set to the variance of the recorded
 * data. The standard deviation is the square root of the variance.
 */
void hg64_mean_variance(hg64* hg, double* pmean, double* pvar);

/*
 * Increase the counts in `target` by the counts recorded in `source`
 */
void hg64_merge(hg64* target, hg64* source);

/*
 * diff = a - b
 */
void hg64_diff(hg64* a, hg64* b, hg64* diff);

/*
 * Get highest key with non-zero value. Returns 0 if all values are 0.
 */
unsigned hg64_max_key(hg64* hg);

/*
 * Get lowest key with non-zero value. Returns 0 if all values are 0.
 */
unsigned hg64_min_key(hg64* hg);

#endif
