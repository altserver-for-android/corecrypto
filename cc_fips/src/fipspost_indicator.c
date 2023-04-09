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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "cc_config.h"
#include "fipspost_indicator.h"

#define STR_EQ(_str_, _expected_) (                    \
    (_str_) != NULL && strcmp(_str_, #_expected_) == 0 \
)

int fips_allowed_mode_(const char *mode, size_t key_byte_length)
{
    if (STR_EQ(mode, ccaes_ctr_crypt_mode) ||
        STR_EQ(mode, ccaes_ecb_encrypt_mode) ||
        STR_EQ(mode, ccaes_ecb_decrypt_mode) ||
        STR_EQ(mode, ccaes_cbc_encrypt_mode) ||
        STR_EQ(mode, ccaes_cbc_decrypt_mode) ||
        STR_EQ(mode, ccaes_ccm_encrypt_mode) ||
        STR_EQ(mode, ccaes_ccm_decrypt_mode) ||
#if (CC_KERNEL)
        STR_EQ(mode, ccdes3_ecb_encrypt_mode) ||
        STR_EQ(mode, ccdes3_ecb_decrypt_mode) ||
#else // (CC_KERNEL)
        STR_EQ(mode, ccaes_cfb_encrypt_mode) ||
        STR_EQ(mode, ccaes_cfb_decrypt_mode) ||
        STR_EQ(mode, ccaes_cfb8_encrypt_mode) ||
        STR_EQ(mode, ccaes_cfb8_decrypt_mode) ||
        STR_EQ(mode, ccaes_ofb_crypt_mode) ||
#endif // (CC_KERNEL)
        STR_EQ(mode, ccwrap_auth_encrypt_withiv) ||
        STR_EQ(mode, ccwrap_auth_decrypt_withiv) ||
        STR_EQ(mode, ccaes_gcm_encrypt_mode) ||
        STR_EQ(mode, ccaes_gcm_decrypt_mode)) {
        return key_byte_length == 16 ||
               key_byte_length == 24 ||
               key_byte_length == 32;
    }

    if (STR_EQ(mode, ccaes_xts_encrypt_mode) ||
        STR_EQ(mode, ccaes_xts_decrypt_mode)) {
        return key_byte_length == 16 ||
               key_byte_length == 32;
    }

#if (CC_USE_L4)
    if (STR_EQ(mode, ccaes_skg_cbc_encrypt_mode) ||
        STR_EQ(mode, ccaes_skg_cbc_decrypt_mode) ||
        STR_EQ(mode, ccaes_skg_ecb_encrypt_mode) ||
        STR_EQ(mode, ccaes_skg_ecb_decrypt_mode)) {
        return key_byte_length == 16 ||
               key_byte_length == 32;
    }
#else
    if (
#if !(CC_KERNEL)
        STR_EQ(mode, ccpad_cts1_encrypt) ||
        STR_EQ(mode, ccpad_cts1_decrypt) ||
        STR_EQ(mode, ccpad_cts2_encrypt) ||
        STR_EQ(mode, ccpad_cts2_decrypt) ||
#endif // !(CC_KERNEL)
        STR_EQ(mode, ccpad_cts3_encrypt) ||
        STR_EQ(mode, ccpad_cts3_decrypt)) {
        return key_byte_length == 16 ||
               key_byte_length == 24 ||
               key_byte_length == 32;
    }
#endif // (CC_USE_L4)

    return 0;
}

int fips_allowed(const char *function, const char *arg1)
{
    int success = 0;

    if (arg1 == NULL) {
        /// FIPS
        success |= STR_EQ(function, fipspost_post_integrity);

        /// Digest
#if !(CC_USE_L4)
        success |= STR_EQ(function, ccmd5_di);
#endif // !(CC_USE_L4)
        success |= STR_EQ(function, ccsha1_di);
        success |= STR_EQ(function, ccsha224_di);
        success |= STR_EQ(function, ccsha256_di);
        success |= STR_EQ(function, ccsha384_di);
        success |= STR_EQ(function, ccsha512_di);
        success |= STR_EQ(function, ccsha512_256_di);

        /// NDRNG
        success |= STR_EQ(function, ccrng_uniform);
    }

    if (arg1 != NULL) {
        /// ECC
        if (STR_EQ(function, ccec_generate_key_fips) ||
            STR_EQ(function, ccec_sign) ||
            STR_EQ(function, ccec_verify)) {
            success = STR_EQ(arg1, ccec_cp_224) ||
                      STR_EQ(arg1, ccec_cp_256) ||
                      STR_EQ(arg1, ccec_cp_384) ||
                      STR_EQ(arg1, ccec_cp_521);
        }

        /// HMAC
        if (STR_EQ(function, cchmac)) {
            success = STR_EQ(arg1, ccsha1_di)   ||
                      STR_EQ(arg1, ccsha224_di) ||
                      STR_EQ(arg1, ccsha256_di) ||
                      STR_EQ(arg1, ccsha384_di) ||
                      STR_EQ(arg1, ccsha512_di) ||
                      STR_EQ(arg1, ccsha512_256_di);
        }

        /// DH / ECDH
#if !(CC_KERNEL)
        if (STR_EQ(function, ccecdh_compute_shared_secret)) {
            success = STR_EQ(arg1, ccec_cp_256) ||
                      STR_EQ(arg1, ccec_cp_384);
        }
#endif // !(CC_KERNEL)

        /// KDF
#if !(CC_USE_L4 || CC_KERNEL)
        if (STR_EQ(function, ccnistkdf_ctr_cmac)) {
            int key_byte_length = atoi(arg1);
            success = key_byte_length == 16 ||
                      key_byte_length == 24 ||
                      key_byte_length == 32;
        }
#endif // !(CC_USE_L4 || CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (STR_EQ(function, ccnistkdf_ctr_hmac) ||
            STR_EQ(function, ccnistkdf_ctr_hmac_fixed) ||
            STR_EQ(function, ccnistkdf_fb_hmac)) {
            success = STR_EQ(arg1, ccsha1_di) ||
                      STR_EQ(arg1, ccsha224_di) ||
                      STR_EQ(arg1, ccsha256_di) ||
                      STR_EQ(arg1, ccsha384_di) ||
                      STR_EQ(arg1, ccsha512_di) ||
            		  STR_EQ(arg1, ccsha512_256_di);
        }
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
        if (STR_EQ(function, ccpbkdf2_hmac) || STR_EQ(function, cchkdf)) {
            success = STR_EQ(arg1, ccsha1_di) ||
                      STR_EQ(arg1, ccsha224_di) ||
                      STR_EQ(arg1, ccsha256_di) ||
                      STR_EQ(arg1, ccsha384_di) ||
                      STR_EQ(arg1, ccsha512_di) ||
            		  STR_EQ(arg1, ccsha512_256_di);
        }

        /// RSA
        if (
            STR_EQ(function, ccrsa_generate_key) ||
            STR_EQ(function, ccrsa_generate_fips186_key)
#if !(TARGET_OS_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
            || STR_EQ(function, ccrsa_sign_pss)
#endif // !(CC_USE_L4)
            || STR_EQ(function, ccrsa_sign_pkcs1v15)
#endif // !(TARGET_OS_BRIDGE && CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
            || STR_EQ(function, ccrsa_encrypt_oaep)
            || STR_EQ(function, ccrsa_decrypt_oaep)
#endif // (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
           ) {
            int key_bit_length = atoi(arg1);
            success = key_bit_length == 2048 ||
                      key_bit_length == 3072 ||
                      key_bit_length == 4096;
        }
        if (STR_EQ(function, ccrsa_verify_pss_digest) ||
            STR_EQ(function, ccrsa_verify_pkcs1v15_digest)) {
            int key_bit_length = atoi(arg1);
            success = key_bit_length == 1024 ||
                      key_bit_length == 2048 ||
                      key_bit_length == 3072 ||
                      key_bit_length == 4096;
        }
    }

    return success;
}
