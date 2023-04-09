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

#include <corecrypto/cc_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccspake.h>
#include "ccspake_internal.h"

// Sanity check for CCSPAKE_TAG_MAX_NBYTES.
cc_static_assert(CCSPAKE_TAG_MAX_NBYTES >= CCSPAKE_HASH_MAX_NBYTES,
    "CCSPAKE_TAG_MAX_NBYTES too small");

/*! @function ccspake_mac_hkdf_hmac_compute
 @abstract Generate an HMAC for key confirmation

 @param ctx     SPAKE2+ context
 @param key_len Length of MAC key
 @param key     MAC key
 @param info_len Length of info
 @param info     Transcript to compute MAC over
 @param t_len   Desired length of the MAC
 @param t       Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
static int ccspake_mac_hkdf_hmac_compute(ccspake_const_ctx_t ctx,
                                         size_t key_len,
                                         const uint8_t *key,
                                         size_t info_len,
                                         const uint8_t *info,
                                         size_t t_len,
                                         uint8_t *t)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di;
    if (t_len > di->output_size) {
        return CCERR_PARAMETER;
    }

    uint8_t digest[CCSPAKE_HASH_MAX_NBYTES];
    cchmac(di, key_len, key, info_len, info, digest);
    cc_memcpy(t, digest, t_len);

    return CCERR_OK;
}

static ccspake_mac_decl() ccspake_mac_hkdf_hmac_sha256_decl = {
    .derive = ccspake_mac_hkdf_derive,
    .compute = ccspake_mac_hkdf_hmac_compute,
};

ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha256()
{
    ccspake_mac_hkdf_hmac_sha256_decl.di = ccsha256_di();
    return (ccspake_const_mac_t)&ccspake_mac_hkdf_hmac_sha256_decl;
}

static ccspake_mac_decl() ccspake_mac_hkdf_hmac_sha512_decl = {
    .derive = ccspake_mac_hkdf_derive,
    .compute = ccspake_mac_hkdf_hmac_compute,
};

ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha512()
{
    ccspake_mac_hkdf_hmac_sha512_decl.di = ccsha512_di();
    return (ccspake_const_mac_t)&ccspake_mac_hkdf_hmac_sha512_decl;
}
