/* Copyright (c) (2011,2012,2014-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cczp_internal.h"
#include "ccn_internal.h"

int cczp_init_ws(cc_ws_t ws, cczp_t zp)
{
    const cc_unit *p = cczp_prime(zp);
    cc_size n = cczp_n(zp);

    // Odd moduli >= 3 supported only.
    if ((p[0] & 1) == 0 || (ccn_n(n, p) == 1 && p[0] < 3)) {
        return CCERR_PARAMETER;
    }

    CCZP_FUNCS(zp) = CCZP_FUNCS_DEFAULT;
    CCZP_BITLEN(zp) = ccn_bitlen(n, p);
    ccn_make_recip_ws(ws, n, CCZP_RECIP(zp), p);

    return CCERR_OK;
}

int cczp_init(cczp_t zp)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_INIT_WORKSPACE_N(cczp_n(zp)));
    int rv = cczp_init_ws(ws, zp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
