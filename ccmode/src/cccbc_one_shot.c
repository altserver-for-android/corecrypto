/* Copyright (c) (2017-2019,2021) Apple Inc. All rights reserved.
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
#include "ccmode_internal.h"
#include <corecrypto/cc_macros.h>
#include "corecrypto/fipspost_trace.h"

int cccbc_one_shot(const struct ccmode_cbc *mode,
                             size_t key_len, const void *key,
                             const void *iv, size_t nblocks,
                             const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    FIPSPOST_TRACE_EVENT;

    int rc;
	cccbc_ctx_decl(mode->size, ctx);
	cccbc_iv_decl(mode->block_size, iv_ctx);
	rc = mode->init(mode, ctx, key_len, key);
    cc_require_or_return(rc == CCERR_OK, rc);
    if (iv) {
        rc = cccbc_set_iv(mode, iv_ctx, iv);
        cc_require(rc == CCERR_OK, clear_ctx_and_exit);
    }
    else {
        cc_clear(mode->block_size, iv_ctx);
    }
    rc = mode->cbc(ctx, iv_ctx, nblocks, in, out);
clear_ctx_and_exit:
    cccbc_ctx_clear(mode->size, ctx);
    return rc;
}
