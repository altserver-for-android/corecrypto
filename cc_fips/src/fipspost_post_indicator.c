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

#include <stdarg.h>
#include "cc_config.h"

#include "fipspost_indicator.h"
#include "fipspost_post_indicator.h"

int fipspost_post_indicator(CC_UNUSED uint32_t fips_mode)
{
    int success = 1;

    /// FIPS
    success &= fips_allowed0(fipspost_post_integrity);

    /// AES
    for (size_t key_byte_length = 16; key_byte_length <= 32; key_byte_length += 8) {
        success &= fips_allowed_mode(ccaes_ecb_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ecb_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cbc_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cbc_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ccm_decrypt_mode, key_byte_length);
#if !(CC_KERNEL)
        success &= fips_allowed_mode(ccaes_cfb8_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb8_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_cfb_decrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_ofb_crypt_mode, key_byte_length);
#endif // !(CC_KERNEL)
        success &= fips_allowed_mode(ccaes_ctr_crypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccaes_gcm_encrypt_mode, key_byte_length); /// GMAC
        success &= fips_allowed_mode(ccaes_gcm_decrypt_mode, key_byte_length); /// GMAC
        success &= fips_allowed_mode(ccwrap_auth_encrypt_withiv, key_byte_length);
        success &= fips_allowed_mode(ccwrap_auth_decrypt_withiv, key_byte_length);
        if (key_byte_length != 24) {
#if (CC_USE_L4)
            success &= fips_allowed_mode(ccaes_skg_cbc_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_cbc_decrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_ecb_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_skg_ecb_decrypt_mode, key_byte_length);
#else
#if !(CC_KERNEL)
            success &= fips_allowed_mode(ccpad_cts1_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts1_decrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts2_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts2_decrypt, key_byte_length);
#endif // !(CC_KERNEL)
            success &= fips_allowed_mode(ccpad_cts3_encrypt, key_byte_length);
            success &= fips_allowed_mode(ccpad_cts3_decrypt, key_byte_length);
#endif // (CC_USE_L4)
            success &= fips_allowed_mode(ccaes_xts_encrypt_mode, key_byte_length);
            success &= fips_allowed_mode(ccaes_xts_decrypt_mode, key_byte_length);
        }
    }

    /// DRBG handled through direct hash or symmetric algorithm verification.

    /// ECC
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_224);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_256);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_384);
    success &= fips_allowed1(ccec_generate_key_fips, ccec_cp_521);
    success &= fips_allowed1(ccec_sign, ccec_cp_224);
    success &= fips_allowed1(ccec_sign, ccec_cp_256);
    success &= fips_allowed1(ccec_sign, ccec_cp_384);
    success &= fips_allowed1(ccec_sign, ccec_cp_521);
    success &= fips_allowed1(ccec_verify, ccec_cp_224);
    success &= fips_allowed1(ccec_verify, ccec_cp_256);
    success &= fips_allowed1(ccec_verify, ccec_cp_384);
    success &= fips_allowed1(ccec_verify, ccec_cp_521);

    /// HMAC
    success &= fips_allowed1(cchmac, ccsha1_di);
    success &= fips_allowed1(cchmac, ccsha224_di);
    success &= fips_allowed1(cchmac, ccsha256_di);
    success &= fips_allowed1(cchmac, ccsha384_di);
    success &= fips_allowed1(cchmac, ccsha512_di);
    success &= fips_allowed1(cchmac, ccsha512_256_di);

    /// DH / ECDH
#if !(CC_KERNEL)
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_256);
    success &= fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_384);
#endif // !(CC_KERNEL)

    /// KDF
#if !(CC_USE_L4 || CC_KERNEL)
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 16);
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 24);
    success &= fips_allowed1(ccnistkdf_ctr_cmac, 32);
#endif // !(CC_USE_L4 || CC_KERNEL)
#if (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha1_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha512_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac, ccsha512_256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha1_di); // KDF_HMAC
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha224_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha256_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha384_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha512_di);
    success &= fips_allowed1(ccnistkdf_ctr_hmac_fixed, ccsha512_256_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha1_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha224_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha256_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha384_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha512_di);
    success &= fips_allowed1(ccnistkdf_fb_hmac, ccsha512_256_di);
#endif // (!(CC_USE_L4 || CC_KERNEL) || (__x86_64__ && CC_KERNEL))
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha1_di);
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha224_di);
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha256_di);
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha384_di);
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha512_di);
    success &= fips_allowed1(ccpbkdf2_hmac, ccsha512_256_di);
    success &= fips_allowed1(cchkdf, ccsha1_di);
    success &= fips_allowed1(cchkdf, ccsha224_di);
    success &= fips_allowed1(cchkdf, ccsha256_di);
    success &= fips_allowed1(cchkdf, ccsha384_di);
    success &= fips_allowed1(cchkdf, ccsha512_di);
    success &= fips_allowed1(cchkdf, ccsha512_256_di);

    /// Digest
#if !(CC_USE_L4)
    success &= fips_allowed0(ccmd5_di);
#endif // !(CC_USE_L4)
    success &= fips_allowed0(ccsha1_di);
    success &= fips_allowed0(ccsha224_di);
    success &= fips_allowed0(ccsha256_di);
    success &= fips_allowed0(ccsha384_di);
    success &= fips_allowed0(ccsha512_di);
    success &= fips_allowed0(ccsha512_256_di);

    /// NDRNG
    success &= fips_allowed0(ccrng_uniform);

    /// RSA
    success &= fips_allowed1(ccrsa_verify_pss_digest, 1024);
    success &= fips_allowed1(ccrsa_verify_pss_digest, 2048);
    success &= fips_allowed1(ccrsa_verify_pss_digest, 3072);
    success &= fips_allowed1(ccrsa_verify_pss_digest, 4096);

    success &= fips_allowed1(ccrsa_verify_pkcs1v15_digest, 1024);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_digest, 2048);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_digest, 3072);
    success &= fips_allowed1(ccrsa_verify_pkcs1v15_digest, 4096);

    success &= fips_allowed1(ccrsa_generate_key, 2048);
    success &= fips_allowed1(ccrsa_generate_key, 3072);
    success &= fips_allowed1(ccrsa_generate_key, 4096);

    success &= fips_allowed1(ccrsa_generate_fips186_key, 2048);
    success &= fips_allowed1(ccrsa_generate_fips186_key, 3072);
    success &= fips_allowed1(ccrsa_generate_fips186_key, 4096);

#if !(TARGET_OS_BRIDGE && CC_KERNEL)
#if !(CC_USE_L4) /// ccrsa_sign_pss is not in L4.
    success &= fips_allowed1(ccrsa_sign_pss, 2048);
    success &= fips_allowed1(ccrsa_sign_pss, 3072);
    success &= fips_allowed1(ccrsa_sign_pss, 4096);
#endif // !(CC_USE_L4)
    success &= fips_allowed1(ccrsa_sign_pkcs1v15, 2048);
    success &= fips_allowed1(ccrsa_sign_pkcs1v15, 3072);
    success &= fips_allowed1(ccrsa_sign_pkcs1v15, 4096);
#endif // !(TARGET_OS_BRIDGE && CC_KERNEL)

#if (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    success &= fips_allowed1(ccrsa_encrypt_oaep, 2048);
    success &= fips_allowed1(ccrsa_encrypt_oaep, 3072);
    success &= fips_allowed1(ccrsa_encrypt_oaep, 4096);
    success &= fips_allowed1(ccrsa_decrypt_oaep, 2048);
    success &= fips_allowed1(ccrsa_decrypt_oaep, 3072);
    success &= fips_allowed1(ccrsa_decrypt_oaep, 4096);
#endif // (!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))

    /// TDES
#if (CC_KERNEL)
    for (size_t key_byte_length = 16; key_byte_length <= 32; key_byte_length += 8) {
        success &= fips_allowed_mode(ccdes3_ecb_encrypt_mode, key_byte_length);
        success &= fips_allowed_mode(ccdes3_ecb_decrypt_mode, key_byte_length);
    }
#endif // (CC_KERNEL)

    /// Not appproved algorithms.
    /// Blowfish.
    success &= !fips_allowed_mode(ccblowfish_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccblowfish_ofb_crypt_mode, 16);

    /// Cast.
    success &= !fips_allowed_mode(cccast_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(cccast_ofb_crypt_mode, 16);

    /// DES - TDES
    success &= !fips_allowed_mode(ccdes_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccdes_ofb_crypt_mode, 16);
#if !(CC_KERNEL)  /// Approved for KERNEL only.
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_ecb_decrypt_mode, 16);
#endif // !(CC_KERNEL)
    success &= !fips_allowed_mode(ccdes3_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccdes3_ofb_crypt_mode, 16);
    success &= !fips_allowed1(ccdh_compute_shared_secret, ccsrp_gp_rfc5054_2048);
    /// DH / ECDH
#if (CC_KERNEL)
    success &= !fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_256);
    success &= !fips_allowed1(ccecdh_compute_shared_secret, ccec_cp_384);
#endif // (CC_KERNEL)
    /// ECIES
    success &= !fips_allowed0(ccecies_encrypt_gcm);
    success &= !fips_allowed0(ccecies_decrypt_gcm);
    /// ED25519
    success &= !fips_allowed0(cced25519_make_key_pair);
    success &= !fips_allowed0(cced25519_sign);
    success &= !fips_allowed0(cced25519_verify);
    /// KDF
    success &= !fips_allowed0(cchkdf);
    /// MD2/4
    success &= !fips_allowed0(ccmd2_di);
    success &= !fips_allowed0(ccmd4_di);
    /// OMAC
    success &= !fips_allowed0(ccomac_update);
    /// RC2/4
    success &= !fips_allowed_mode(ccrc2_ecb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ecb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cbc_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cbc_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_decrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_cfb8_encrypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ctr_crypt_mode, 16);
    success &= !fips_allowed_mode(ccrc2_ofb_crypt_mode, 16);
    success &= !fips_allowed0(ccrc4);
    /// RIPEMD
    success &= !fips_allowed0(ccrmd160_di);
    /// RSA
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 1024);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 1024);
#if !(!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_encrypt_oaep, 4096);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 2048);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 3072);
    success &= !fips_allowed1(ccrsa_decrypt_oaep, 4096);
#endif // !(!(CC_USE_L4 || CC_KERNEL) || (CC_KERNEL && __x86_64__))

    /// These tests must fail.
    success &= !fips_allowed0(NULL);
    success &= !fips_allowed1(NULL, 42);
    success &= !fips_allowed_mode(ccaes_ecb_encrypt_mode, 12);
    success &= !fips_allowed_mode(ccdes3_ecb_encrypt_mode, 42);
    success &= !fips_allowed_mode(ccdes_ecb_encrypt_mode, 12);

    return !success;
}
