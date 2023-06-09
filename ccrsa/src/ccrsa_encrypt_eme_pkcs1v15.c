/* Copyright (c) (2011,2013,2015,2018-2021) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

int ccrsa_encrypt_eme_pkcs1v15_ws(cc_ws_t ws,
                                  ccrsa_pub_ctx_t key,
                                  struct ccrng_state *rng,
                                  size_t *r_size, uint8_t *r,
                                  size_t s_size, const uint8_t *s)
{
    size_t m_size = ccrsa_block_size(key);
    cc_size n = ccrsa_ctx_n(key);

    if ((m_size == 0) || ccn_is_zero_or_one(n, ccrsa_ctx_m(key))) {
        return CCRSA_KEY_ERROR;
    }

    if (*r_size < m_size) {
        return CCRSA_INVALID_INPUT;
    }

    *r_size = m_size;

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    ccn_clear(n, tmp);

    int rv = ccrsa_eme_pkcs1v15_encode(rng, m_size, tmp, s_size, s);
    if (rv) {
        goto errOut;
    }

    rv = ccrsa_pub_crypt_ws(ws, key, tmp, tmp);
    if (rv) {
        goto errOut;
    }

    /* we need to write leading zeroes if necessary */
    rv = ccn_write_uint_padded_ct(n, tmp, m_size, r);
    if (rv > 0) {
        rv = CCERR_OK;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccrsa_encrypt_eme_pkcs1v15(ccrsa_pub_ctx_t key,
                               struct ccrng_state *rng,
                               size_t *r_size, uint8_t *r,
                               size_t s_size, const uint8_t *s)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_ENCRYPT_EME_PKCS1V15_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_encrypt_eme_pkcs1v15_ws(ws, key, rng, r_size, r, s_size, s);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
