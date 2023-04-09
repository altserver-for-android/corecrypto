/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
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
#include "ccsae.h"
#include "ccsae_priv.h"
#include "cczp_internal.h"
#include "ccsae_internal.h"

CC_IGNORE_VLA_WARNINGS

int ccsae_get_keys(ccsae_const_ctx_t ctx, uint8_t *kck, uint8_t *pmk, uint8_t *pmkid)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATE(CONFIRMATION_BOTH);

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    cczp_const_t zq = ccec_cp_zq(cp);

    uint8_t scratch[tn];
    cc_unit pmkid_b[n];

    int rv = cczp_add(zq, pmkid_b, ccsae_ctx_commitscalar(ctx), ccsae_ctx_peer_commitscalar(ctx));
    if (rv) {
        return rv;
    }

    ccn_write_uint_padded(n, pmkid_b, tn, scratch);

    cc_memcpy(kck, ccsae_ctx_KCK(ctx), CCSAE_KCK_PMK_SIZE);
    cc_memcpy(pmk, ccsae_ctx_PMK(ctx), CCSAE_KCK_PMK_SIZE);
    cc_assert(CCSAE_PMKID_SIZE <= tn);
    cc_memcpy(pmkid, scratch, CCSAE_PMKID_SIZE);

    return CCERR_OK;
}

CC_RESTORE_VLA_WARNINGS
