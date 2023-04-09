/* Copyright (c) (2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_debug.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_ecdsa.h"

CC_IGNORE_VLA_WARNINGS

static int fipspost_post_ecdsa_sign(uint32_t fips_mode,
                                    ccec_const_cp_t cp,
                                    const struct ccdigest_info *di,
                                    size_t msg_nbytes,
                                    uint8_t *msg_bytes,
                                    size_t dQ_nbytes,
                                    uint8_t *dQ_bytes,
                                    size_t k_nbytes,
                                    uint8_t *k_bytes,
                                    size_t r_nbytes,
                                    uint8_t *r_bytes,
                                    size_t s_nbytes,
                                    uint8_t *s_bytes)
{
    struct ccrng_ecfips_test_state ectest_rng;
    struct ccrng_state *rng = (struct ccrng_state *)&ectest_rng;

    size_t cp_bits = ccec_cp_prime_bitlen(cp);
    size_t di_bits = di->output_size * 8;

    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    int ret = ccec_x963_import_priv(cp, dQ_nbytes, dQ_bytes, key);
    if (ret != 0) {
        failf("failed ccec_x963_import_priv (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        k_nbytes -= 1;
    }

    ccrng_ecfips_test_init(&ectest_rng, k_nbytes, k_bytes);

    uint8_t sig[ccec_sign_max_size(cp)];
    size_t sig_len = sizeof(sig);

    ret = ccec_sign_msg(key, di, msg_nbytes, msg_bytes, &sig_len, sig, rng);
    if (ret != 0) {
        failf("failed ccec_sign_msg (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_GENERIC_FAILURE;
    }

    uint8_t r[ccec_signature_r_s_size(ccec_ctx_pub(key))];
    uint8_t s[ccec_signature_r_s_size(ccec_ctx_pub(key))];

    ret = ccec_extract_rs(ccec_ctx_pub(key), sig_len, sig, r, s);
    if (ret != 0) {
        failf("failed ccec_extract_rs (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_GENERIC_FAILURE;
    }

    if (memcmp(r, r_bytes, r_nbytes)) {
        failf("failed ECDSA_P%zu_SHA%zu KAT (r)", cp_bits, di_bits);
        return CCPOST_KAT_FAILURE;
    }

    if (memcmp(s, s_bytes, s_nbytes)) {
        failf("failed ECDSA_P%zu_SHA%zu KAT (s)", cp_bits, di_bits);
        return CCPOST_KAT_FAILURE;
    }

    return 0;
}

const struct fipspost_ecdsa_sign_kat {
    ccec_const_cp_t (*cp)(void);
    const struct ccdigest_info *(*di)(void);
    size_t msg_len;
    uint8_t *msg;
    size_t dq_len;
    uint8_t *dq;
    size_t k_len;
    uint8_t *k;
    size_t r_len;
    uint8_t *r;
    size_t s_len;
    uint8_t *s;
} sign_kat_tvs[] = {
#include "../test_vectors/fipspost_post_ecdsa_sign.kat"
};

static int fipspost_post_ecdsa_kat_sign(uint32_t fips_mode)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(sign_kat_tvs); i++) {
        const struct fipspost_ecdsa_sign_kat *kat = &sign_kat_tvs[i];

        ccec_const_cp_t cp = kat->cp();
        const struct ccdigest_info *di = kat->di();

        size_t cp_bits = ccec_cp_prime_bitlen(cp);
        size_t di_bits = di->output_size * 8;

        int ret = fipspost_post_ecdsa_sign(fips_mode, cp, di,
                                           kat->msg_len, kat->msg,
                                           kat->dq_len, kat->dq,
                                           kat->k_len, kat->k,
                                           kat->r_len, kat->r,
                                           kat->s_len, kat->s);
        if (ret != 0) {
            failf("failed ECDSA_P%zu_SHA%zu_SIG KAT #%zu", cp_bits, di_bits, i);
            return CCPOST_KAT_FAILURE;
        }
    }

    return 0;
}

static int fipspost_post_ecdsa_verify(uint32_t fips_mode,
                                      ccec_const_cp_t cp,
                                      const struct ccdigest_info *di,
                                      size_t msg_nbytes,
                                      uint8_t *msg_bytes,
                                      size_t Q_nbytes,
                                      uint8_t *Q_bytes,
                                      size_t sig_nbytes,
                                      uint8_t *sig_bytes)
{
    size_t cp_bits = ccec_cp_prime_bitlen(cp);
    size_t di_bits = di->output_size * 8;

    ccec_pub_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    int ret = ccec_x963_import_pub(cp, Q_nbytes, Q_bytes, key);
    if (ret != 0) {
        failf("failed ccec_x963_import_pub (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_GENERIC_FAILURE;
    }

    uint8_t sig[sig_nbytes];
    memcpy(sig, sig_bytes, sig_nbytes);
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        sig[0] ^= 0x5a;
    }

    ret = ccec_verify_msg(key, di, msg_nbytes, msg_bytes, sig_nbytes, sig, NULL);
    if (ret != 0) {
        failf("failed ccec_verify_msg (P-%zu/SHA-%zu): %d", cp_bits, di_bits, ret);
        return CCPOST_KAT_FAILURE;
    }

    return 0;
}

const struct fipspost_ecdsa_verify_kat {
    ccec_const_cp_t (*cp)(void);
    const struct ccdigest_info *(*di)(void);
    size_t msg_len;
    uint8_t *msg;
    size_t q_len;
    uint8_t *q;
    size_t sig_len;
    uint8_t *sig;
} verify_kat_tvs[] = {
#include "../test_vectors/fipspost_post_ecdsa_verify.kat"
};

static int fipspost_post_ecdsa_kat_verify(uint32_t fips_mode)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(verify_kat_tvs); i++) {
        const struct fipspost_ecdsa_verify_kat *kat = &verify_kat_tvs[i];

        ccec_const_cp_t cp = kat->cp();
        const struct ccdigest_info *di = kat->di();

        size_t cp_bits = ccec_cp_prime_bitlen(cp);
        size_t di_bits = di->output_size * 8;

        int ret = fipspost_post_ecdsa_verify(fips_mode, cp, di,
                                             kat->msg_len, kat->msg,
                                             kat->q_len, kat->q,
                                             kat->sig_len, kat->sig);
        if (ret != 0) {
            failf("failed ECDSA_P%zu_SHA%zu_VER KAT #%zu", cp_bits, di_bits, i);
            return CCPOST_KAT_FAILURE;
        }
    }

    return 0;
}

// Test ECDSA
int fipspost_post_ecdsa(uint32_t fips_mode)
{
    int ret_s = fipspost_post_ecdsa_kat_sign(fips_mode);
    int ret_v = fipspost_post_ecdsa_kat_verify(fips_mode);
    return ret_s | ret_v;
}

CC_RESTORE_VLA_WARNINGS
