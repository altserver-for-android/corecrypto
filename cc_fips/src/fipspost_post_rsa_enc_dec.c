/* Copyright (c) (2017,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include "cc_memory.h"

#include <corecrypto/ccrsa.h>
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccsha2.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_rsa_enc_dec.h"

CC_IGNORE_VLA_WARNINGS

#include "fipspost_post_rsa_enc_dec.inc"

#if !(CC_USE_L4 || CC_KERNEL)
static int fipspost_post_rsa_oaep_decrypt(uint32_t fips_mode,
                                          ccrsa_full_ctx_t full_key,
                                          size_t ciphertext_nbytes,
                                          const uint8_t *ciphertext,
                                          size_t message_nbytes,
                                          const uint8_t *message)
{
    cc_size n = ccrsa_ctx_n(full_key);
    size_t plaintext_nbytes = ccn_sizeof_n(n);
    uint8_t plaintext[plaintext_nbytes];

    uint8_t ct[ciphertext_nbytes];
    memcpy(ct, ciphertext, ciphertext_nbytes);

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        ct[0] ^= 0xaa;
    }

    int rv = ccrsa_decrypt_oaep(full_key, ccsha256_di(),
                                &plaintext_nbytes, plaintext,
                                sizeof(ct), ct,
                                0, NULL);
    if (rv) {
        failf("ccrsa_decrypt_oaep");
        return CCPOST_GENERIC_FAILURE;
    }

    if (plaintext_nbytes != message_nbytes) {
        failf("len(plaintext) != len(message)");
        return CCPOST_KAT_FAILURE;
    }

    if (memcmp(plaintext, message, message_nbytes)) {
        failf("plaintext != message");
        return CCPOST_KAT_FAILURE;
    }

    return rv;
}

static int fipspost_post_rsa_oaep_consistency(uint32_t fips_mode)
{
    cc_size n = FIPS_RSA_OAEP_KEY_N;
    ccrsa_full_ctx_decl_n(n, full_key);
    ccrsa_ctx_n(full_key) = n;

    int rv = ccrsa_import_priv(full_key, sizeof(FIPS_RSA_OAEP_KEY), FIPS_RSA_OAEP_KEY);
    if (rv) {
        failf("ccrsa_import_priv");
        return CCPOST_GENERIC_FAILURE;
    }

    size_t ciphertext_nbytes = ccn_sizeof_n(n);
    uint8_t ciphertext[ciphertext_nbytes];

    struct ccrng_state *rng = ccrng(NULL);
    ccrsa_pub_ctx_t pub_key = ccrsa_ctx_public(full_key);
    rv = ccrsa_encrypt_oaep(pub_key, ccsha256_di(), rng,
                            &ciphertext_nbytes, ciphertext,
                            sizeof(FIPS_RSA_OAEP_MESSAGE), FIPS_RSA_OAEP_MESSAGE,
                            0, NULL);
    if (rv) {
        failf("ccrsa_encrypt_oaep");
        return CCPOST_GENERIC_FAILURE;
    }

    rv = fipspost_post_rsa_oaep_decrypt(fips_mode, full_key,
                                        ciphertext_nbytes, ciphertext,
                                        sizeof(FIPS_RSA_OAEP_MESSAGE),
                                        FIPS_RSA_OAEP_MESSAGE);
    if (rv) {
        failf("fipspost_post_rsa_oaep_consistency");
    }

    return rv;
}

static int fipspost_post_rsa_oaep_kat(uint32_t fips_mode)
{
    cc_size n = FIPS_RSA_OAEP_KEY_N;
    ccrsa_full_ctx_decl_n(n, full_key);
    ccrsa_ctx_n(full_key) = n;

    int rv = ccrsa_import_priv(full_key, sizeof(FIPS_RSA_OAEP_KEY), FIPS_RSA_OAEP_KEY);
    if (rv) {
        failf("ccrsa_import_priv");
        return CCPOST_GENERIC_FAILURE;
    }

    rv = fipspost_post_rsa_oaep_decrypt(fips_mode, full_key,
                                        sizeof(FIPS_RSA_OAEP_CIPHERTEXT),
                                        FIPS_RSA_OAEP_CIPHERTEXT,
                                        sizeof(FIPS_RSA_OAEP_MESSAGE),
                                        FIPS_RSA_OAEP_MESSAGE);
    if (rv) {
        failf("fipspost_post_rsa_oaep_kat");
    }

    return rv;
}
#endif // !(CC_USE_L4 || CC_KERNEL)

int fipspost_post_rsa_enc_dec(uint32_t fips_mode)
{
    int rv = CCERR_OK;
#if !(CC_USE_L4 || CC_KERNEL)
    rv |= fipspost_post_rsa_oaep_consistency(fips_mode);
    rv |= fipspost_post_rsa_oaep_kat(fips_mode);
#endif
    return rv;
}

CC_RESTORE_VLA_WARNINGS
