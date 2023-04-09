/* Copyright (c) (2011,2014-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdh.h>
#include "ccdh_internal.h"
#include <corecrypto/cc_priv.h>

/* DEPRECATED - Urgent to migrate to ccdh_compute_shared_secret */
static int ccdh_compute_key_ws(cc_ws_t ws, ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key, cc_unit *r)
{
    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);

    struct ccrng_state *rng = ccrng(NULL);
    if (!rng) {
        return CCERR_INTERNAL;
    }

    cc_size n = ccdh_gp_n(gp);
    CC_DECL_BP_WS(ws, bp);

    uint8_t *tmp = (uint8_t *)CC_ALLOC_WS(ws, n);
    size_t tmp_len = CC_BITLEN_TO_BYTELEN(ccdh_gp_prime_bitlen(gp));
    cc_clear(tmp_len, tmp);

    /* Validate the public key */
    int rv = ccdh_compute_shared_secret_ws(ws, private_key, public_key, &tmp_len, tmp, rng);
    if (rv) {
        goto cleanup;
    }

    rv = ccn_read_uint(n, r, tmp_len, tmp);

cleanup:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key, cc_unit *r)
{
    CC_ENSURE_DIT_ENABLED

    ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCDH_COMPUTE_KEY_WORKSPACE_N(ccdh_gp_n(gp)));
    int rv = ccdh_compute_key_ws(ws, private_key, public_key, r);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
