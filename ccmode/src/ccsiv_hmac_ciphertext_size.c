/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccmode_siv_hmac.h>
#include <corecrypto/ccmode_siv_hmac_priv.h>
#include "ccmode_siv_hmac_internal.h"

size_t ccsiv_hmac_ciphertext_size(ccsiv_hmac_ctx *ctx, size_t plaintext_size)
{
    CC_ENSURE_DIT_ENABLED

    return plaintext_size + _CCMODE_SIV_HMAC_TAG_LENGTH(ctx);
}
