/* Copyright (c) (2011,2012,2015,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>
#include "cc_priv.h"

int ccn_random_bits(cc_size nbits, cc_unit *r, struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccn_nof(nbits);

    int rv = ccrng_generate(rng, ccn_sizeof_n(n), r);
    if (rv) {
        return rv;
    }

    cc_size lbits = nbits & (CCN_UNIT_BITS - 1);

    cc_unit lbits_nz; // lbits ≠ 0?
    CC_HEAVISIDE_STEP(lbits_nz, lbits);

    // lbits := (lbits == 0) ? CCN_UNIT_BITS : lbits
    lbits += CCN_UNIT_BITS & (lbits_nz - 1);

    // If lbits > 0, shift the mask to the right.
    r[n - 1] &= CCN_UNIT_MASK >> (CCN_UNIT_BITS - lbits);

    return rv;
}
