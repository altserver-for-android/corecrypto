/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"
#include "ccn_internal.h"
#include <corecrypto/ccrng.h>

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define SCA_MASK_MSBIT (CC_UNIT_C(1) << (SCA_MASK_BITSIZE - 1))

cc_static_assert(SCA_MASK_N == 1, "needs to fit in a word");

// Helper function to allow WORKSPACE_N() function generation for cczp_power_blinded_ws().
CC_INLINE int cczp_power_blinded_div_mask_ws(cc_ws_t ws, cc_size n, cc_unit *q,  const cc_unit *e, cc_unit *b, cc_unit mask)
{
    return ccn_div_euclid_ws(ws, n, q, SCA_MASK_N, b, n, e, SCA_MASK_N, &mask);
}

CC_PURE cc_size CCZP_POWER_BLINDED_DIV_MASK_WORKSPACE_N(cc_size n)
{
    return CCN_DIV_EUCLID_WORKSPACE_N(n, SCA_MASK_N);
}

int cczp_power_blinded_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e, struct ccrng_state *rng)
{
    cc_size n = cczp_n(zp);

    // We require s < p.
    if (ccn_cmp(n, s, cczp_prime(zp)) >= 0) {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *q = CC_ALLOC_WS(ws, n);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    cc_unit mask;
    int rv = ccn_random_bits(SCA_MASK_BITSIZE, &mask, rng);
    if (rv) {
        goto cleanup;
    }
    mask |= SCA_MASK_MSBIT;

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(mask);

    // e = floor(e / mask) * mask + (e mod mask) = q * mask + b
    cc_unit b;
    rv = cczp_power_blinded_div_mask_ws(ws, n, q, e, &b, mask);
    if (rv) {
        goto cleanup;
    }

    // t := s^q
    rv = cczp_power_ws(ws, zp, t, s, ccn_bitsof_n(n) - SCA_MASK_BITSIZE + 1, q);
    if (rv) {
        goto cleanup;
    }

    // r := s^b
    rv = cczp_power_ws(ws, zp, r, s, SCA_MASK_BITSIZE, &b);
    if (rv) {
        goto cleanup;
    }

    // q := s^q^mask
    rv = cczp_power_ws(ws, zp, q, t, SCA_MASK_BITSIZE, &mask);
    if (rv) {
        goto cleanup;
    }

    // r := s^b * s^q^mask
    cczp_mul_ws(ws, zp, r, r, q);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}
