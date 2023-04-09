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
#include "ccrsabssa.h"
#include <corecrypto/cc_macros.h>
#include "ccrsa_internal.h"
#include <corecrypto/ccsha2.h>
#include "ccrsabssa_internal.h"

CC_IGNORE_VLA_WARNINGS

#pragma mark Ciphersuites Specific Support
#define CCRSABSSA_MAX_DIGEST_OUTPUT_SIZE CCSHA384_OUTPUT_SIZE

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa2048_sha384 = {
        .rsa_modulus_nbits = 2048,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa3072_sha384 = {
        .rsa_modulus_nbits = 3072,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa4096_sha384 = {
        .rsa_modulus_nbits = 4096,
        .di = ccsha384_di,
        .salt_size_nbytes = 48,
};

#pragma mark Deprecated ciphersuites to be removed (rdar://79722663 (Remove deprecated RSABSSA ciphersuites))

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa2048_sha256 = {
        .rsa_modulus_nbits = 2048,
        .di = ccsha256_di,
        .salt_size_nbytes = 48,
};

const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa3072_sha256 = {
        .rsa_modulus_nbits = 3072,
        .di = ccsha256_di,
        .salt_size_nbytes = 48,
};

static bool validate_rsa_key_size_for_ciphersuite(const struct ccrsabssa_ciphersuite *ciphersuite, ccrsa_pub_ctx_t pubKey) {
    size_t modulus_n_bits = ccrsa_pubkeylength(pubKey);
    size_t expected_size = ciphersuite->rsa_modulus_nbits;
    return modulus_n_bits == expected_size;
}

#pragma mark Signature Verification Wrapper with ciphersuite security parameters

static int ccrsabssa_verify_signature(const struct ccrsabssa_ciphersuite *ciphersuite,
                                      const ccrsa_pub_ctx_t key,
                                      const uint8_t *msg,
                                      const size_t msg_nbytes,
                                      const uint8_t *signature, const size_t signature_nbytes)
{
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);
    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(modulus_n_bytes == signature_nbytes, CCERR_PARAMETER);
    
    const struct ccdigest_info* di = ciphersuite->di();
    
    return ccrsa_verify_pss_msg(key, di, di, msg_nbytes, msg, signature_nbytes, signature, ciphersuite->salt_size_nbytes, NULL);
}

int ccrsabssa_blind_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                            const ccrsa_pub_ctx_t key,
                            const uint8_t *msg, const size_t msg_nbytes,
                            uint8_t *blinding_inverse, size_t blinding_inverse_nbytes,
                            uint8_t *blinded_msg, size_t blinded_msg_nbytes,
                            struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    int rc = CCERR_PARAMETER;
    
    // Setting up variables for ciphersuite.
    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);
    const struct ccdigest_info* di = ciphersuite->di();
    
    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(blinding_inverse_nbytes == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinded_msg_nbytes == modulus_n_bytes, CCERR_PARAMETER);
    
    const cc_size emBits = modulus_n_bits-1; //as defined in §8.1.1 of PKCS1-V2
    const cc_size emLen = cc_ceiling(emBits, 8); //In theory, emLen can be one byte less than modBytes
    
    uint8_t msg_hash[CCRSABSSA_MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_nbytes, msg, msg_hash);
    uint8_t salt[ciphersuite->salt_size_nbytes];
    rc = ccrng_generate(rng, ciphersuite->salt_size_nbytes, salt);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    const cc_size modWords = ccrsa_ctx_n(key);
    cc_unit EM[modWords];
    EM[0]=EM[modWords-1] = 0; //in case emLen<modWord* sizeof(cc_unit), zeroize
    
    const size_t ofs = modWords*sizeof(cc_unit)-emLen;
    cc_assert(ofs<=sizeof(cc_unit)); //EM can only be one cc_unit larger
    
    rc = ccrsa_emsa_pss_encode(di, di, sizeof(salt), salt, di->output_size, msg_hash, emBits, (uint8_t *)EM+ofs);
    cc_require_or_return(rc == CCERR_OK, rc);
    cc_require_or_return(CCERR_OK == ccrsa_emsa_pss_decode(di, di, ciphersuite->salt_size_nbytes, di->output_size, msg_hash, emBits, (uint8_t *)EM + ofs), CCERR_INTERNAL);
    
    ccn_swap(modWords, EM);
    
    cc_unit r[modWords];
    rc = cczp_generate_non_zero_element(ccrsa_ctx_zm(key), rng, r);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    cc_unit r_inv [modWords];
    rc = cczp_inv(ccrsa_ctx_zm(key), r_inv, r);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    cc_unit X[modWords];
    rc = ccrsa_pub_crypt(key, X, r);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    cc_unit z [modWords];
    cczp_mul(ccrsa_ctx_zm(key), z, EM, X);
    
    rc = ccn_write_uint_padded_ct(modWords, z, modulus_n_bytes, blinded_msg);
    cc_require_or_return(rc >= 0, rc);
    
    rc = ccn_write_uint_padded_ct(modWords, r_inv, modulus_n_bytes, blinding_inverse);
    cc_require_or_return(rc >= 0, rc);
    
    return CCERR_OK;
}



int ccrsabssa_unblind_signature(const struct ccrsabssa_ciphersuite *ciphersuite,
                                const ccrsa_pub_ctx_t key,
                                const uint8_t* blind_signature, const size_t blind_signature_nbytes,
                                const uint8_t* blinding_inverse, const size_t blinding_inverse_nbytes,
                                const uint8_t* msg, const size_t msg_nbytes,
                                uint8_t *unblinded_signature, const size_t unblinded_signature_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, key), CCERR_PARAMETER);
    size_t modulus_n_bits = ccrsa_pubkeylength(key);
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(blind_signature_nbytes     == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinding_inverse_nbytes    == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(unblinded_signature_nbytes == modulus_n_bytes, CCERR_PARAMETER);
    
    int rc = 0;
    
    const cc_size modWords = ccrsa_ctx_n(key);
    cc_unit z[modWords];
    rc = ccn_read_uint(modWords, z, blind_signature_nbytes, blind_signature);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    cc_unit blindInverse[modWords];
    rc = ccn_read_uint(modWords, blindInverse, modulus_n_bytes, blinding_inverse);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    cc_unit s[modWords];
    cczp_mul(ccrsa_ctx_zm(key), s, z, blindInverse);
    
    rc = ccn_write_uint_padded_ct(modWords, s, modulus_n_bytes, unblinded_signature);
    cc_require_or_return(rc >= 0, rc);
    
    return ccrsabssa_verify_signature(ciphersuite, key, msg, msg_nbytes, unblinded_signature, unblinded_signature_nbytes);
}

#pragma mark Signer Functions

int ccrsabssa_sign_blinded_message(const struct ccrsabssa_ciphersuite *ciphersuite,
                                   const ccrsa_full_ctx_t key,
                                   const uint8_t * blinded_message, const size_t blinded_message_nbytes,
                                   uint8_t *signature, const size_t signature_nbytes,
                                   struct ccrng_state *blinding_rng)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(validate_rsa_key_size_for_ciphersuite(ciphersuite, ccrsa_ctx_public(key)), CCERR_PARAMETER);
    size_t modulus_n_bits = ccrsa_pubkeylength(ccrsa_ctx_public(key));
    size_t modulus_n_bytes = cc_ceiling(modulus_n_bits, 8);
    cc_require_or_return(signature_nbytes       == modulus_n_bytes, CCERR_PARAMETER);
    cc_require_or_return(blinded_message_nbytes == modulus_n_bytes, CCERR_PARAMETER);
    
    const cc_size modWords = ccrsa_ctx_n(key);
    cc_unit signatureCCN[modWords];
    
    cc_unit blindedMessage[modWords];
    int rc = ccn_read_uint(modWords, blindedMessage, blinded_message_nbytes, blinded_message);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    rc = ccrsa_priv_crypt_blinded(blinding_rng, key, signatureCCN, blindedMessage);
    cc_require_or_return(rc == CCERR_OK, rc);
    
    rc = ccn_write_uint_padded_ct(modWords, signatureCCN, signature_nbytes, signature);
    cc_require_or_return(rc >= 0, rc);
    
    return CCERR_OK;
}

CC_RESTORE_VLA_WARNINGS
