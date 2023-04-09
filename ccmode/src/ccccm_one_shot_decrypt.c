/* Copyright (c) (2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode.h>
#include <corecrypto/cc_macros.h>

int ccccm_one_shot_decrypt(const struct ccmode_ccm *mode,
                             size_t key_nbytes,
                             const uint8_t *cc_sized_by(key_nbytes) key,
                             size_t nonce_nbytes,
                             const uint8_t *cc_sized_by(nonce_nbytes) nonce,
                             size_t nbytes,
                             const uint8_t *cc_sized_by(nbytes) encrypted_plaintext,
                             uint8_t *cc_sized_by(nbytes) plaintext,
                             size_t adata_nbytes,
                             const uint8_t *cc_sized_by(adata_nbytes) adata,
                             size_t mac_tag_nbytes,
                             const uint8_t *cc_sized_by(mac_tag_nbytes) mac_tag)
{
    CC_ENSURE_DIT_ENABLED

    int rc;
    cc_require_or_return(mode->enc_mode == false, CCMODE_INVALID_CALL_SEQUENCE);
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
    rc = mode->init(mode, ctx, key_nbytes, key);
    if (rc == 0) {
        rc = mode->set_iv(ctx, nonce_ctx, nonce_nbytes, nonce, mac_tag_nbytes, adata_nbytes, nbytes);
    }
    if (rc == 0) {
        rc = mode->cbcmac(ctx, nonce_ctx, adata_nbytes, adata);
    }
    if (rc == 0) {
        rc = mode->ccm(ctx, nonce_ctx, nbytes, encrypted_plaintext, plaintext);
    }
    if (rc == 0) {
        rc = ccccm_finalize_and_verify_tag(mode, ctx, nonce_ctx, mac_tag);
    }
    ccccm_ctx_clear(mode->size, ctx);
    ccccm_nonce_clear(mode->nonce_size, nonce_ctx);

    return rc;
}
