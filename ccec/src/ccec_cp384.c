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

// 2^768 mod P.
static const cc_unit RR_MOD_P[CCN384_N] = {
    CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,02,00,00,00,00,ff,ff,ff,fe,00,00,00,00,00,00,00,02,00,00,00,00,ff,ff,ff,fe,00,00,00,01)
};

// 2^384 mod P.
static const cc_unit R1_MOD_P[CCN384_N] = {
    CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,01)
};

/*! @function ccn_addmul1_p384
 @abstract Computes r += p384 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
static cc_unit ccn_addmul1_p384(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // v * 0xffffffffffffffff
    cc_dunit v2 = ((cc_dunit)v << 64) - v;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[0] + v1;
    r[0] = (cc_unit)tmp;

    // * 0xffffffff00000000
    tmp = (cc_dunit)r[1] + (v1 << 32) + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0xfffffffffffffffe
    tmp = (cc_dunit)r[2] + (v2 - v) + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[3] + v2 + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[4] + v2 + (tmp >> 64);
    r[4] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[5] + v2 + (tmp >> 64);
    r[5] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p384(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0xffffffff
    tmp = (cc_dunit)r[0] + v1;
    r[0] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[1] + (tmp >> 32);
    r[1] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[2] + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0xfffffffe
    tmp = (cc_dunit)r[4] + (v1 - v) + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[5] + v1 + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[6] + v1 + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[7] + v1 + (tmp >> 32);
    r[7] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[8] + v1 + (tmp >> 32);
    r[8] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[9] + v1 + (tmp >> 32);
    r[9] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[10] + v1 + (tmp >> 32);
    r[10] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[11] + v1 + (tmp >> 32);
    r[11] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p384(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN384_N, r, ccec_cp_p(ccec_cp_384()), v);
}
#endif

/*! @function ccn_p384_redc
 @abstract Computes r := t / R (mod p384) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p384_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // m := ((t mod R) * p0inv) mod R
    // t := (t + m * p) / R
    //   where p0inv = -p[0]^(-1) (mod 2^w)
    for (cc_size i = 0; i < CCN384_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
#if (CCN_UNIT_SIZE == 8)
        t[i] = ccn_addmul1_p384(&t[i], t[i] + (t[i] << 32)); // * 0x100000001
#else
        t[i] = ccn_addmul1_p384(&t[i], t[i]);
#endif
    }

    // Optional final reduction.
    cc_unit s = ccn_add(CCN384_N, &t[CCN384_N], &t[CCN384_N], t);
    s ^= ccn_sub(CCN384_N, t, &t[CCN384_N], cczp_prime(zp));
    ccn_mux(CCN384_N, s, r, &t[CCN384_N], t);

    // Sanity check.
    cc_assert(ccn_cmp(CCN384_N, r, cczp_prime(zp)) < 0);
}

/*! @function ccn_p384_mul_ws
 @abstract Multiplies two 384-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p384_mul_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN384_N, rbig, x, y);
    ccn_p384_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p384_sqr_ws
 @abstract Squares a 384-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p384_sqr_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, CCN384_N, rbig, x);
    ccn_p384_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p384_is_one_ws
 @abstract Returns whether x = R (mod p384), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p384). False otherwise.
 */
CC_NONNULL_ALL
static bool ccn_p384_is_one_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(CCN384_N, x, R1_MOD_P) == 0;
}

/*! @function ccn_p384_to_ws
 @abstract Computes r := x * R (mod p384) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p384_to_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN384_N, rbig, x, RR_MOD_P);
    ccn_p384_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p384_from_ws
 @abstract Computes r := x / R (mod p384) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p384_from_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN384_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * CCN384_N, rbig, CCN384_N, x);
    ccn_p384_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

#pragma workspace-override cczp_mul_ws ccn_p384_mul_ws
#pragma workspace-override cczp_sqr_ws ccn_p384_sqr_ws
#pragma workspace-override cczp_is_one_ws ccn_p384_is_one_ws
#pragma workspace-override cczp_to_ws ccn_p384_to_ws
#pragma workspace-override cczp_from_ws ccn_p384_from_ws

static cczp_funcs_decl(cczp_p384_funcs_c,
    ccn_p384_mul_ws,
    ccn_p384_sqr_ws,
    cczp_mod_default_ws,
    cczp_inv_default_ws,
    cczp_sqrt_default_ws,
    ccn_p384_to_ws,
    ccn_p384_from_ws,
    ccn_p384_is_one_ws);

static const ccec_cp_decl(384) ccec_cp384_c =
{
    .hp = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = &cczp_p384_funcs_c
    },
    .p = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,00,00,00,00,00,00,00,00,ff,ff,ff,ff)
    },
    .pr = {
        CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,01),1
    },
    .b = {
        CCN384_C(cd,08,11,4b,60,4f,bf,f9,b6,2b,21,f4,1f,02,20,94,e3,37,4b,ee,94,93,8a,e2,77,f2,20,9b,19,20,02,2e,f7,29,ad,d8,7a,4c,32,ec,08,11,88,71,9d,41,2d,cc)
    },
    .gx = {
        CCN384_C(aa,87,ca,22,be,8b,05,37,8e,b1,c7,1e,f3,20,ad,74,6e,1d,3b,62,8b,a7,9b,98,59,f7,41,e0,82,54,2a,38,55,02,f2,5d,bf,55,29,6c,3a,54,5e,38,72,76,0a,b7)
    },
    .gy = {
        CCN384_C(36,17,de,4a,96,26,2c,6f,5d,9e,98,bf,92,92,dc,29,f8,f4,1d,bd,28,9a,14,7c,e9,da,31,13,b5,f0,b8,c0,0a,60,b1,ce,1d,7e,81,9d,7a,43,1d,7c,90,ea,0e,5f)
    },
    .hq = {
        .n = CCN384_N,
        .bitlen = 384,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,c7,63,4d,81,f4,37,2d,df,58,1a,0d,b2,48,b0,a7,7a,ec,ec,19,6a,cc,c5,29,73)
    },
    .qr = {
        CCN384_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,38,9c,b2,7e,0b,c8,d2,20,a7,e5,f2,4d,b7,4f,58,85,13,13,e6,95,33,3a,d6,8d),1
    }
};

ccec_const_cp_t ccec_cp_384_c(void)
{
    return (ccec_const_cp_t)&ccec_cp384_c;
}

CC_WEAK_IF_SMALL_CODE
ccec_const_cp_t ccec_cp_384(void)
{
    return (ccec_const_cp_t)&ccec_cp384_c;
}
