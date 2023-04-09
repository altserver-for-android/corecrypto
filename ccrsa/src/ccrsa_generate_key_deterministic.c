/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccaes.h>

CC_IGNORE_VLA_WARNINGS

int ccrsa_generate_key_deterministic(size_t nbits, ccrsa_full_ctx_t fk,
                                     size_t e_nbytes, const uint8_t *e,
                                     size_t entropy_nbytes, const uint8_t *entropy,
                                     size_t nonce_nbytes, const uint8_t *nonce,
                                     uint32_t flags,
                                     struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    // This is the only mode currently supported.
    if (flags != CCRSA_GENKEY_DETERMINISTIC_LEGACY) {
        return CCERR_PARAMETER;
    }

    struct ccdrbg_nistctr_custom custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 16,
        .strictFIPS = 0,
        .use_df = 1,
    };

    static struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)state;

    int rv = ccdrbg_init(&info, drbg_state, entropy_nbytes, entropy, nonce_nbytes, nonce, 0, NULL);
    if (rv) {
        return rv;
    }

    struct ccrng_drbg_state drbg_ctx;
    rv = ccrng_drbg_init_withdrbg(&drbg_ctx, &info, drbg_state);
    if (rv) {
        return rv;
    }

    struct ccrng_state *det_rng = (struct ccrng_state *)&drbg_ctx;
    rv = ccrsa_generate_key_internal(nbits, fk, e_nbytes, e, det_rng, rng);
    if (rv) {
        return rv;
    }

    ccdrbg_done(&info, drbg_state);
    return CCERR_OK;
}

CC_RESTORE_VLA_WARNINGS
