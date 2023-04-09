/* Copyright (c) (2010-2012,2014-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

static void ccn_mod_521_ws(CC_UNUSED cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    cc_assert(cczp_n(zp) == CCN521_N);
    cc_unit t[CCN521_N];
    cc_unit t2[CCN521_N];
    cc_unit borrow;

#if CCN_UNIT_SIZE == 1
    ccn_shift_right(CCN521_N - 1, t2, &a[CCN521_N - 1], 1); // r = a521,...,a1041
    t2[CCN521_N - 1] += a[CCN521_N - 1] & CC_UNIT_C(1);
    t2[CCN521_N - 1] += ccn_add(CCN521_N - 1,t2,t2,a);
#else
    ccn_shift_right(CCN521_N, t2, &a[CCN512_N], 9);  // r = a521,...,a1041
    t2[CCN512_N] += a[CCN512_N] & CC_UNIT_C(0x1ff);  // r += (a512,...,a520)*2^512
    t2[CCN512_N] += ccn_add(CCN512_N,t2,t2,a);         // r += a0,...,a511
#endif
    borrow=ccn_sub(CCN521_N, t, t2, cczp_prime(zp));
    ccn_mux(CCN521_N, borrow, r, t2, t);

    /* Sanity for debug */
    cc_assert(ccn_cmp(CCN521_N, r, cczp_prime(zp)) < 0);
}

#pragma workspace-override cczp_mod_ws ccn_mod_521_ws

static cczp_funcs_decl_mod(cczp_p521_funcs, ccn_mod_521_ws);

static const ccec_cp_decl(521) ccec_cp521 =
{
    .hp = {
        .n = CCN521_N,
        .bitlen = 521,
        .funcs = &cczp_p521_funcs
    },
    .p = {
        CCN528_C(01,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .pr = {
        CCN528_C(02,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01)
    },
    .b = {

        CCN528_C(00,51,95,3e,b9,61,8e,1c,9a,1f,92,9a,21,a0,b6,85,40,ee,a2,da,72,5b,99,b3,15,f3,b8,b4,89,91,8e,f1,09,e1,56,19,39,51,ec,7e,93,7b,16,52,c0,bd,3b,b1,bf,07,35,73,df,88,3d,2c,34,f1,ef,45,1f,d4,6b,50,3f,00)
    },
    .gx = {

        CCN528_C(00,c6,85,8e,06,b7,04,04,e9,cd,9e,3e,cb,66,23,95,b4,42,9c,64,81,39,05,3f,b5,21,f8,28,af,60,6b,4d,3d,ba,a1,4b,5e,77,ef,e7,59,28,fe,1d,c1,27,a2,ff,a8,de,33,48,b3,c1,85,6a,42,9b,f9,7e,7e,31,c2,e5,bd,66)
    },
    .gy = {
        CCN528_C(01,18,39,29,6a,78,9a,3b,c0,04,5c,8a,5f,b4,2c,7d,1b,d9,98,f5,44,49,57,9b,44,68,17,af,bd,17,27,3e,66,2c,97,ee,72,99,5e,f4,26,40,c5,50,b9,01,3f,ad,07,61,35,3c,70,86,a2,72,c2,40,88,be,94,76,9f,d1,66,50)
    },
    .hq = {
        .n = CCN521_N,
        .bitlen = 521,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN528_C(01,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fa,51,86,87,83,bf,2f,96,6b,7f,cc,01,48,f7,09,a5,d0,3b,b5,c9,b8,89,9c,47,ae,bb,6f,b7,1e,91,38,64,09)
    },
    .qr = {
        CCN528_C(02,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,05,ae,79,78,7c,40,d0,69,94,80,33,fe,b7,08,f6,5a,2f,c4,4a,36,47,76,63,b8,51,44,90,48,e1,6e,c7,9b,f7)
    }
};

ccec_const_cp_t ccec_cp_521(void)
{
    return (ccec_const_cp_t)&ccec_cp521;
}
