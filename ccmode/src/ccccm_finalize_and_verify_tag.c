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
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_priv.h>
#include "ccmode_internal.h"

int ccccm_finalize_and_verify_tag(const struct ccmode_ccm *mode, ccccm_ctx *ctx, ccccm_nonce *nonce_ctx, const uint8_t *cc_indexable mac)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t outTag[CCM_MAX_TAG_SIZE];
    cc_require_or_return(mode->enc_mode == false, CCMODE_INVALID_CALL_SEQUENCE);
    int rc = mode->finalize(ctx, nonce_ctx, outTag);
    cc_require(rc == CCERR_OK, errOut);
    rc = cc_cmp_safe(CCMODE_CCM_KEY_MAC_LEN(nonce_ctx), outTag, mac) == 0 ? CCERR_OK : CCMODE_INTEGRITY_FAILURE;
  
    // If authentication failed, don't return the improperly computed tag
    if (rc!= CCERR_OK) {
        cc_clear(CCMODE_CCM_KEY_MAC_LEN(nonce_ctx), outTag);
    }
errOut:
    return rc;
}

