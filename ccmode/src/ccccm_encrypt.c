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

int ccccm_encrypt(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, size_t nbytes, const uint8_t *cc_sized_by(nbytes) plaintext, uint8_t *cc_sized_by(nbytes) encrypted_plaintext)
{
    CC_ENSURE_DIT_ENABLED

    cc_require_or_return(mode->enc_mode == true, CCMODE_INVALID_CALL_SEQUENCE);
    return mode->ccm(ctx, nonce_ctx, nbytes, plaintext, encrypted_plaintext);
}
