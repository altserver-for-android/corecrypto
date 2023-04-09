/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccspake.h>
#include <corecrypto/cchkdf.h>

#include "cc_workspaces.h"
#include "ccspake_internal.h"
#include "cc_priv.h"

static const uint8_t KDF_LABEL[16] = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y', 's' };

int ccspake_mac_hkdf_derive(ccspake_const_ctx_t ctx, size_t ikm_len, const uint8_t *ikm, size_t keys_len, uint8_t *keys)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;
    cc_assert(keys_len == di->output_size);

    size_t aad_len = ccspake_ctx_aad_len(ctx);

    const uint8_t salt[CCSPAKE_HASH_MAX_NBYTES] = { 0 };
    uint8_t prk[CCSPAKE_HASH_MAX_NBYTES];

    // HKDF-Extract.
    int rv = cchkdf_extract(di, di->output_size, salt, ikm_len, ikm, prk);
    if (rv) {
        return rv;
    }

    // HKDF-Expand.
    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, di->output_size, prk);
    cchmac_update(di, hc, sizeof(KDF_LABEL), KDF_LABEL);

    if (aad_len) {
        cchmac_update(di, hc, aad_len, ccspake_ctx_aad(ctx));
    }

    uint8_t i = 1;
    cchmac_update(di, hc, 1, &i);
    cchmac_final(di, hc, keys);

    cchmac_di_clear(di, hc);
    cc_clear(sizeof(prk), prk);
    return rv;
}

/*! @function ccspake_ikm_hash_length
 @abstract Hash `length` to `dc` as a 64-byte little-endian integer.

 @param ctx     SPAKE2+ context
 @param dc      Hash context
 @param length  Number to write
 */
CC_NONNULL_ALL
static void ccspake_ikm_hash_length(ccspake_const_ctx_t ctx,
                                    ccdigest_ctx_t dc,
                                    uint64_t length)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;

    uint8_t le_length[8];
    cc_store64_le(length, le_length);
    ccdigest_update(di, dc, sizeof(le_length), le_length);
}

/*! @function ccspake_ikm_hash_point_ws
 @abstract Hash 0x04 + `xy` to `dc`, prefixed by the total length.

 @param ws   Workspace
 @param ctx  SPAKE2+ context
 @param dc   Hash context
 @param xy   Coordinates x and y.
 */
CC_NONNULL_ALL
static void ccspake_ikm_hash_point_ws(cc_ws_t ws,
                                      ccspake_const_ctx_t ctx,
                                      ccdigest_ctx_t dc,
                                      const cc_unit *xy)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t p_len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *tmp = (uint8_t *)CC_ALLOC_WS(ws, n);

    // length
    ccspake_ikm_hash_length(ctx, dc, p_len * 2 + 1);

    // format
    const uint8_t uncompressed = 0x04;
    ccdigest_update(di, dc, 1, &uncompressed);

    // x-coordinate
    ccn_write_uint_padded(n, xy, p_len, tmp);
    ccdigest_update(di, dc, p_len, tmp);

    // y-coordinate
    ccn_write_uint_padded(n, xy + n, p_len, tmp);
    ccdigest_update(di, dc, p_len, tmp);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccspake_derive_shared_key_ws
 @abstract Derives the shared key when the protocol completes

 @param ws     Workspace
 @param ctx    SPAKE2+ context
 @param sk     Target buffer
 */
CC_NONNULL_ALL
static void ccspake_derive_shared_key_ws(cc_ws_t ws, ccspake_const_ctx_t ctx, uint8_t *sk)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t q_len = ccec_cp_order_size(cp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *tmp = (uint8_t *)CC_ALLOC_WS(ws, n);

    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);

    // Write len(X) || X || len(Y) || Y.
    if (ccspake_ctx_is_prover(ctx)) {
        ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_XY(ctx));
        ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_Q(ctx));
    } else {
        ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_Q(ctx));
        ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_XY(ctx));
    }

    // Write len(Z) || Z.
    ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_Z(ctx));

    // Write len(V) || V.
    ccspake_ikm_hash_point_ws(ws, ctx, dc, ccspake_ctx_V(ctx));

    // Write len(w0) || w0.
    ccspake_ikm_hash_length(ctx, dc, q_len);
    ccn_write_uint_padded(n, ccspake_ctx_w0(ctx), q_len, tmp);
    ccdigest_update(di, dc, q_len, tmp);

    // Derive.
    ccdigest_final(di, dc, sk);
    ccdigest_di_clear(di, dc);

    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccspake_mac_compute_internal_ws
 @abstract Generic function to derive MAC keys and compute MACs

 @param ws     Workspace
 @param ctx    SPAKE2+ context
 @param key    Key to derive MAC keys from (of length `h_len / 2`)
 @param use_k1 Flag to tell whether to compute a MAC with K1 or K2
 @param x      x-coordinate of the point to confirm
 @param y      y-coordinate of the point to confirm
 @param t_len  Length of t
 @param t      Target buffer
 */
CC_NONNULL_ALL
static int ccspake_mac_compute_internal_ws(cc_ws_t ws,
                                           ccspake_const_ctx_t ctx,
                                           const uint8_t *key,
                                           bool use_k1,
                                           const cc_unit *x,
                                           const cc_unit *y,
                                           size_t t_len,
                                           uint8_t *t)
{
    size_t h_len = ccspake_ctx_mac(ctx)->di->output_size;
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t p_len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);

    uint8_t mac_keys[CCSPAKE_HASH_MAX_NBYTES];
    int rv = ccspake_ctx_mac(ctx)->derive(ctx, h_len / 2, key, h_len, mac_keys);
    if (rv != 0) {
        return rv;
    }

    CC_DECL_BP_WS(ws, bp);
    uint8_t *info = (uint8_t *)CC_ALLOC_WS(ws, n * 2 + 1);

    info[0] = 0x04;

    // Write coordinates.
    ccn_write_uint_padded(n, x, p_len, info + 1);
    ccn_write_uint_padded(n, y, p_len, info + 1 + p_len);

    uint8_t *mkey = mac_keys + (!use_k1 * (h_len / 2));
    size_t pt_size = ccspake_sizeof_point(ccspake_ctx_scp(ctx));
    rv = ccspake_ctx_mac(ctx)->compute(ctx, h_len / 2, mkey, pt_size, info, t_len, t);

    cc_clear(sizeof(mac_keys), mac_keys);
    cc_clear(sizeof(info), info);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

/*! @function ccspake_mac_compute_ws
 @abstract Generate a MAC for key confirmation.

 @param ws    Workspace
 @param ctx   SPAKE2+ context
 @param t_len Desired length of the MAC
 @param t     Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int ccspake_mac_compute_ws(cc_ws_t ws, ccspake_ctx_t ctx, size_t t_len, uint8_t *t)
{
    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_VERIFY);

    uint8_t key[CCSPAKE_HASH_MAX_NBYTES];
    ccspake_derive_shared_key_ws(ws, ctx, key);

    int rv = ccspake_mac_compute_internal_ws(
        ws, ctx, key, !ccspake_ctx_is_prover(ctx), ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx), t_len, t);

    cc_clear(sizeof(key), key);

    if (rv == CCERR_OK) {
        CCSPAKE_ADD_STATE(MAC_GENERATE);
    }

    return rv;
}

int ccspake_mac_compute(ccspake_ctx_t ctx, size_t t_len, uint8_t *t)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_MAC_COMPUTE_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_mac_compute_ws(ws, ctx, t_len, t);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}

/*! @function ccspake_mac_verify_and_get_session_key_ws
 @abstract Verify a MAC to confirm and derive the shared key.

 @param ws     Workspace
 @param ctx    SPAKE2+ context
 @param t_len  Length of the MAC
 @param t      MAC sent by the peer
 @param sk_len Desired length of the shared key
 @param sk     Output buffer for the shared key

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
static int ccspake_mac_verify_and_get_session_key_ws(cc_ws_t ws,
                                                     ccspake_ctx_t ctx,
                                                     size_t t_len,
                                                     const uint8_t *t,
                                                     size_t sk_len,
                                                     uint8_t *sk)
{
    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_GENERATE);

    size_t h_len = ccspake_ctx_mac(ctx)->di->output_size;
    if (sk_len != h_len / 2) {
        return CCERR_PARAMETER;
    }

    if (t_len > CCSPAKE_TAG_MAX_NBYTES) {
        return CCERR_PARAMETER;
    }

    uint8_t key[CCSPAKE_HASH_MAX_NBYTES];
    ccspake_derive_shared_key_ws(ws, ctx, key);

    uint8_t tag[CCSPAKE_TAG_MAX_NBYTES];
    int rv = ccspake_mac_compute_internal_ws(
        ws, ctx, key, ccspake_ctx_is_prover(ctx), ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx), t_len, tag);

    if (rv != 0) {
        goto cleanup;
    }

    if (cc_cmp_safe(t_len, t, tag)) {
        rv = CCERR_INTEGRITY;
        goto cleanup;
    }

    cc_memcpy(sk, key + h_len / 2, h_len / 2);

    CCSPAKE_ADD_STATE(MAC_VERIFY);

cleanup:
    cc_clear(sizeof(tag), tag);
    cc_clear(sizeof(key), key);

    return rv;
}

int ccspake_mac_verify_and_get_session_key(ccspake_ctx_t ctx, size_t t_len, const uint8_t *t, size_t sk_len, uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_MAC_VERIFY_AND_GET_SESSION_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_mac_verify_and_get_session_key_ws(ws, ctx, t_len, t, sk_len, sk);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
