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
#include "cc_macros.h"
#include "ccsae_priv.h"
#include "ccsae_internal.h"
#include "ccec_internal.h"
#include "cchmac.h"

CC_IGNORE_VLA_WARNINGS

static int ccsae_generate_commitment_shared(ccsae_ctx_t ctx, ccec_const_projective_point_t PWE_projective, uint8_t *commitment)
{
    int error = CCERR_PARAMETER;

    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    size_t tn = ccec_cp_prime_size(cp);
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);

    // [WPA3] 12.4.5.2: Generate rand & mask
    cc_require(ccec_generate_scalar_fips_retry(cp, rng, ccsae_ctx_rand(ctx)) == CCERR_OK, out);
    cc_require(ccec_generate_scalar_fips_retry(cp, rng, ccsae_ctx_S_mask(ctx)) == CCERR_OK, out);

    // CE = mask * PWE
    cc_require(ccec_mult_blinded(cp, (ccec_projective_point_t)ccsae_ctx_CE(ctx), ccsae_ctx_S_mask(ctx), PWE_projective, rng) ==
                   CCERR_OK,
               out);

    cc_require(ccec_affinify(cp, (ccec_affine_point_t)ccsae_ctx_CE(ctx), (ccec_projective_point_t)ccsae_ctx_CE(ctx)) == CCERR_OK,
               out);

    // CE = -CE
    cczp_negate(ccec_cp_zp(cp), ccsae_ctx_CE_y(ctx), ccsae_ctx_CE_y(ctx));

    // [WPA3] 12.4.5.3: Generate the Commit Scalar
    cc_require(cczp_add((cczp_const_t)ccec_cp_zq(cp), ccsae_ctx_commitscalar(ctx), ccsae_ctx_rand(ctx), ccsae_ctx_S_mask(ctx)) ==
                   CCERR_OK,
               out);
    cc_require(!ccn_is_zero_or_one(n, ccsae_ctx_commitscalar(ctx)), out);

    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_commitscalar(ctx), tn, commitment) >= 0, out);
    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_CE_x(ctx), tn, commitment + tn) >= 0, out);
    cc_require(ccn_write_uint_padded_ct(n, ccsae_ctx_CE_y(ctx), tn, commitment + 2 * tn) >= 0, out);

    error = ccec_affinify(cp, (ccec_affine_point_t)ccsae_ctx_PWE(ctx), PWE_projective);
    cc_require(error == CCERR_OK, out);

    error = CCERR_OK;
out:
    return error;
}

int ccsae_generate_commitment_init(ccsae_ctx_t ctx)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATE(INIT);

    ccsae_ctx_current_loop_iteration(ctx) = 1; // Hunting and pecking always starts with the counter = 1
    ccsae_ctx_found_qr(ctx) = ccsae_ctx_temp_lsb(ctx) = 0;

    CCSAE_ADD_STATE(COMMIT_INIT);
    return CCERR_OK;
}

int ccsae_generate_commitment_partial(ccsae_ctx_t ctx,
                                      const uint8_t *A,
                                      size_t A_nbytes,
                                      const uint8_t *B,
                                      size_t B_nbytes,
                                      const uint8_t *password,
                                      size_t password_nbytes,
                                      const uint8_t *identifier,
                                      size_t identifier_nbytes,
                                      uint8_t max_num_iterations)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATES(COMMIT_UPDATE, COMMIT_INIT);
    if (max_num_iterations == 0) {
        return CCERR_PARAMETER;
    }

    if (A_nbytes > CCSAE_MAX_IDENTITY_SIZE || B_nbytes > CCSAE_MAX_IDENTITY_SIZE) {
        return CCERR_PARAMETER;
    }

    if (password_nbytes > CCSAE_MAX_PASSWORD_IDENTIFIER_SIZE || identifier_nbytes > CCSAE_MAX_PASSWORD_IDENTIFIER_SIZE) {
        return CCERR_PARAMETER;
    }

    // The current loop iteration starts at 1 so subtract to get the number of iterations we have performed
    uint8_t loop_iterations_complete = ccsae_ctx_current_loop_iteration(ctx) - 1;
    if (loop_iterations_complete == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }

    uint8_t actual_iterations =
        (uint8_t)CC_MIN_EVAL(max_num_iterations, ccsae_ctx_max_loop_iterations(ctx) - loop_iterations_complete);

    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cc_size n = ccec_cp_n(cp);
    uint8_t LSB = ccsae_ctx_temp_lsb(ctx);
    uint8_t found_qr = ccsae_ctx_found_qr(ctx);

    size_t keySize = A_nbytes + B_nbytes;
    uint8_t key[2 * CCSAE_MAX_IDENTITY_SIZE];

    ccsae_lexographic_order_key(A, A_nbytes, B, B_nbytes, key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSAE_Y2_FROM_X_WORKSPACE_N(n));

    // Initialize per-iteration HMAC.
    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, keySize, key);
    cchmac_update(di, hc, password_nbytes, password);
    if (identifier != NULL) {
        cchmac_update(di, hc, identifier_nbytes, identifier);
    }

    // Save initial, per-iteration HMAC state.
    uint8_t state[cchmac_ctx_size(MAX_DIGEST_STATE_SIZE, MAX_DIGEST_BLOCK_SIZE)];
    cc_memcpy(state, hc, cchmac_di_size(di));

    for (uint8_t counter = 0; counter < actual_iterations; counter++) {
        uint8_t actual_counter = ccsae_ctx_current_loop_iteration(ctx) + counter;

        // Compute next seed and value.
        cc_memcpy(hc, state, cchmac_di_size(di));
        cchmac_update(di, hc, 1, &actual_counter);
        cchmac_final(di, hc, ccsae_ctx_S_PWD_SEED(ctx));
        ccsae_gen_password_value(ctx, ccsae_ctx_S_PWD_SEED(ctx), ccsae_ctx_S_PWD_VALUE(ctx));

        ccn_mux(n, found_qr, ccsae_ctx_PWE_x(ctx), ccsae_ctx_PWE_x(ctx), ccsae_ctx_S_PWD_VALUE(ctx));
        CC_MUXU(LSB, found_qr, LSB, ccsae_ctx_S_PWD_SEED_LSB(ctx, di) & 1);
        found_qr |= ccsae_y2_from_x_ws(ws, cp, ccsae_ctx_PWE_y(ctx), ccsae_ctx_PWE_x(ctx));
    }

    CC_FREE_WORKSPACE(ws);
    cchmac_di_clear(di, hc);

    ccsae_ctx_temp_lsb(ctx) = LSB;
    ccsae_ctx_found_qr(ctx) = found_qr;
    ccsae_ctx_current_loop_iteration(ctx) += actual_iterations;
    CCSAE_ADD_STATE(COMMIT_UPDATE);

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 == ccsae_ctx_max_loop_iterations(ctx)) {
        return CCERR_OK;
    }
    return CCSAE_GENERATE_COMMIT_CALL_AGAIN;
}

int ccsae_generate_commitment_finalize(ccsae_ctx_t ctx, uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATE(COMMIT_UPDATE);
    int result = CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS;
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    ccec_point_decl_cp(cp, PWE_projective);
    cc_size n = ccec_cp_n(cp);
    bool LSB = ccsae_ctx_temp_lsb(ctx) & 1;

    if (ccsae_ctx_current_loop_iteration(ctx) - 1 < ccsae_ctx_max_loop_iterations(ctx)) {
        return CCSAE_NOT_ENOUGH_COMMIT_PARTIAL_CALLS;
    }
    cc_require(ccsae_ctx_found_qr(ctx), cleanup); // Returns CCSAE_HUNTPECK_EXCEEDED_MAX_TRIALS

    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_require(cczp_sqrt(zp, ccsae_ctx_CE_y(ctx), ccsae_ctx_PWE_y(ctx)) == CCERR_OK, cleanup);
    cc_require(cczp_from(zp, ccsae_ctx_PWE_y(ctx), ccsae_ctx_CE_y(ctx)) == CCERR_OK, cleanup);
    cczp_negate(zp, ccsae_ctx_S_PWE_ym1(ctx), ccsae_ctx_PWE_y(ctx));
    ccn_mux(n, ccn_bit(ccsae_ctx_PWE_y(ctx), 0) ^ LSB, ccsae_ctx_PWE_y(ctx), ccsae_ctx_S_PWE_ym1(ctx), ccsae_ctx_PWE_y(ctx));

    /* 12.4.5.3: Generate the Commit Element
     * We already know ccsase_ctx_PWE is a valid point because of the above loop,
     * so we can simply call ccec_projectify.
     */
    cc_require(ccec_projectify(cp, PWE_projective, (ccec_const_affine_point_t)ccsae_ctx_PWE(ctx), rng) == CCERR_OK, cleanup);

    result = ccsae_generate_commitment_shared(ctx, PWE_projective, commitment);
    cc_require(result == CCERR_OK, cleanup);
    CCSAE_ADD_STATE(COMMIT_GENERATED);
cleanup:
    ccn_clear(n, ccsae_ctx_S_PWE_ym1(ctx));
    ccn_clear(n, ccsae_ctx_S_mask(ctx));
    return result;
}

int ccsae_generate_commitment(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *password,
                              size_t password_nbytes,
                              const uint8_t *identifier,
                              size_t identifier_nbytes,
                              uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    int error = ccsae_generate_commitment_init(ctx);
    if (error != CCERR_OK) {
        return error;
    }

    error = ccsae_generate_commitment_partial(
        ctx, A, A_nbytes, B, B_nbytes, password, password_nbytes, identifier, identifier_nbytes, SAE_HUNT_AND_PECK_ITERATIONS);
    if (error != CCERR_OK) {
        return error;
    }

    return ccsae_generate_commitment_finalize(ctx, commitment);
}

int ccsae_generate_h2c_commit(ccsae_ctx_t ctx,
                              const uint8_t *A,
                              size_t A_nbytes,
                              const uint8_t *B,
                              size_t B_nbytes,
                              const uint8_t *pt,
                              size_t pt_nbytes,
                              uint8_t *commitment)
{
    CC_ENSURE_DIT_ENABLED

    CCSAE_EXPECT_STATE(INIT);
    int error = CCERR_PARAMETER;

    const struct ccdigest_info *di = ccsae_ctx_di(ctx);
    ccec_const_cp_t cp = ccsae_ctx_cp(ctx);
    cczp_const_t zq = ccec_cp_zq(cp);
    struct ccrng_state *rng = ccsae_ctx_rng(ctx);
    cc_size n = ccec_cp_n(cp);
    cc_size nd = ccn_nof_size(di->output_size);

    cc_unit qm1[n];
    cc_unit val[nd];
    uint8_t key[2 * CCSAE_MAX_IDENTITY_SIZE];
    uint8_t val_bytes[di->output_size];
    uint8_t zeros[di->output_size];
    cc_clear(di->output_size, zeros);

    ccec_pub_ctx_decl_cp(cp, PT);
    ccec_point_decl_cp(cp, PT_projective);
    ccec_point_decl_cp(cp, PWE_projective);

    cc_require((A_nbytes <= CCSAE_MAX_IDENTITY_SIZE) && (B_nbytes <= CCSAE_MAX_IDENTITY_SIZE), out);
    size_t keySize = A_nbytes + B_nbytes;
    ccsae_lexographic_order_key(A, A_nbytes, B, B_nbytes, key);

    cchmac(di, di->output_size, zeros, keySize, key, val_bytes);
    cc_require(ccn_read_uint(nd, val, di->output_size, val_bytes) == CCERR_OK, out);

    ccn_set(n, qm1, cczp_prime(zq));
    qm1[0] &= ~CC_UNIT_C(1);
    cc_require(ccn_mod(n, val, nd, val, n, qm1) == CCERR_OK, out);
    ccn_add1(n, val, val, 1); // 1 <= val <= q - 1

    ccec_ctx_init(cp, PT);
    cc_require(ccec_import_pub(cp, pt_nbytes, pt, PT) == CCERR_OK, out);

    error = ccec_validate_pub_and_projectify(cp, PT_projective, (ccec_const_affine_point_t)ccec_ctx_point(PT), rng);
    cc_require(error == CCERR_OK, out);

    error = ccec_mult_blinded(cp, PWE_projective, val, PT_projective, rng);
    cc_require(error == CCERR_OK, out);

    error = ccsae_generate_commitment_shared(ctx, PWE_projective, commitment);
    cc_require(error == CCERR_OK, out);
    CCSAE_ADD_STATE(COMMIT_GENERATED);
out:
    return error;
}

CC_RESTORE_VLA_WARNINGS
