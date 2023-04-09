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

#include <corecrypto/cc_config.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

#if CCN_UNIT_SIZE == 8

// 2^512 mod P.
static const cc_unit RR_MOD_P[CCN224_N] = {
    CCN224_C(ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,00,00,00,01)
};

// 2^256 mod P.
static const cc_unit R1_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00)
};

#else

// 2^448 mod P.
static const cc_unit RR_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fe,00,00,00,00,00,00,00,00,00,00,00,01)
};

// 2^224 mod P.
static const cc_unit R1_MOD_P[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

#endif

// c1, the largest integer such that 2^c1 divides p - 1.
static const size_t SQRT_C1 = 96;

// c2 = (p - 1) / (2^c1)
// c3 = (c2 - 1) / 2
static const cc_unit SQRT_C3[CCN224_N] = {
    CCN224_C(00,00,00,00,00,00,00,00,00,00,00,00,7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
};

// c2 = (p - 1) / (2^c1)
// c4 = 0xb (a non-square value in F)
// c5 = c4^c2 in F.
static const cc_unit SQRT_C5[CCN224_N] = {
#if CCN_UNIT_SIZE == 8
    CCN224_C(dc,58,4a,70,48,83,1b,2a,b4,0e,42,70,e8,ff,4d,ec,bd,bc,c8,60,04,ab,76,ab,3d,fe,35,12)
#else
    CCN224_C(dd,4f,6d,00,14,bb,49,f6,fc,ae,2c,30,99,6f,56,28,14,df,d3,a4,6a,c7,64,62,0a,f2,e8,1a)
#endif
};

/*! @function ccn_addmul1_p224
 @abstract Computes r += p224 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x0000000000000001
    tmp = (cc_dunit)r[0] + v;
    r[0] = (cc_unit)tmp;

    // * 0xffffffff00000000
    tmp = (cc_dunit)r[1] + (v1 << 32) + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[2] + (((cc_dunit)v << 64) - v) + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[3] + v1 + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0x00000001
    tmp = (cc_dunit)r[0] + v;
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

    // * 0xffffffff
    tmp = (cc_dunit)r[4] + v1 + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[5] + v1 + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[6] + v1 + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p224(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN224_N, r, ccec_cp_p(ccec_cp_224()), v);
}
#endif

/*! @function ccn_p224_redc
 @abstract Computes r := t / R (mod p224) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p224_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // m := ((t mod R) * p0inv) mod R
    // t := (t + m * p) / R
    //   where p0inv = -p[0]^(-1) (mod 2^w)
    for (cc_size i = 0; i < CCN224_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1_p224(&t[i], -t[i]);
    }

    // Optional final reduction.
    cc_unit s = ccn_add(CCN224_N, &t[CCN224_N], &t[CCN224_N], t);
    s ^= ccn_sub(CCN224_N, t, &t[CCN224_N], cczp_prime(zp));
    ccn_mux(CCN224_N, s, r, &t[CCN224_N], t);

    // Sanity check.
    cc_assert(ccn_cmp(CCN224_N, r, cczp_prime(zp)) < 0);
}

/*! @function ccn_p224_mul_ws
 @abstract Multiplies two 224-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p224_mul_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN224_N, rbig, x, y);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p224_sqr_ws
 @abstract Squares a 224-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p224_sqr_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, CCN224_N, rbig, x);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p224_is_one_ws
 @abstract Returns whether x = R (mod p224), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p224). False otherwise.
 */
CC_NONNULL_ALL
bool ccn_p224_is_one_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(CCN224_N, x, R1_MOD_P) == 0;
}

/*! @function ccn_p224_sqrt_ws
 @abstract Computes r := x^(1/2) (mod p224) via constant-time Tonelli-Shanks.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Square root of x
 @param x   Quadratic residue
 */
int ccn_p224_sqrt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    return cczp_sqrt_tonelli_shanks_precomp_ws(ws, zp, r, x, SQRT_C1, SQRT_C3, SQRT_C5);
}

/*! @function ccn_p224_to_ws
 @abstract Computes r := x * R (mod p224) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
void ccn_p224_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cczp_mul_ws(ws, zp, r, x, RR_MOD_P);
}

/*! @function ccn_p224_from_ws
 @abstract Computes r := x / R (mod p224) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p224_from_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN224_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * CCN224_N, rbig, CCN224_N, x);
    ccn_p224_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

#pragma workspace-override cczp_mul_ws ccn_p224_mul_ws
#pragma workspace-override cczp_sqr_ws ccn_p224_sqr_ws
#pragma workspace-override cczp_is_one_ws ccn_p224_is_one_ws
#pragma workspace-override cczp_sqrt_ws ccn_p224_sqrt_ws
#pragma workspace-override cczp_to_ws ccn_p224_to_ws
#pragma workspace-override cczp_from_ws ccn_p224_from_ws

static cczp_funcs_decl(cczp_p224_funcs,
    ccn_p224_mul_ws,
    ccn_p224_sqr_ws,
    cczp_mod_default_ws,
    cczp_inv_default_ws,
    ccn_p224_sqrt_ws,
    ccn_p224_to_ws,
    ccn_p224_from_ws,
    ccn_p224_is_one_ws);

static const ccec_cp_decl(224) ccec_cp224 =
{
    .hp = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = &cczp_p224_funcs
    },
    .p = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,01)
    },
    .pr = {
        CCN232_C(01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .b = {
#if CCN_UNIT_SIZE == 8
        CCN224_C(7f,c0,2f,93,3d,ce,ba,98,c8,52,81,51,10,7a,c2,f3,cc,f0,13,10,e7,68,cd,f6,63,c0,59,cd)
#else
        CCN224_C(9c,3f,a6,33,7f,c0,2f,93,3d,ce,ba,98,c8,52,81,50,74,3b,1c,c0,cc,f0,13,10,e7,68,cd,f7)
#endif
    },
    .gx = {
        CCN224_C(b7,0e,0c,bd,6b,b4,bf,7f,32,13,90,b9,4a,03,c1,d3,56,c2,11,22,34,32,80,d6,11,5c,1d,21)
    },
    .gy = {
        CCN224_C(bd,37,63,88,b5,f7,23,fb,4c,22,df,e6,cd,43,75,a0,5a,07,47,64,44,d5,81,99,85,00,7e,34)
    },
    .hq = {
        .n = CCN224_N,
        .bitlen = 224,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN224_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,16,a2,e0,b8,f0,3e,13,dd,29,45,5c,5c,2a,3d)
    },
    .qr = {
        CCN232_C(01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,e9,5d,1f,47,0f,c1,ec,22,d6,ba,a3,a3,d5,c3)
    }
};

ccec_const_cp_t ccec_cp_224_c(void)
{
    return (ccec_const_cp_t)&ccec_cp224;
}

CC_WEAK_IF_SMALL_CODE
ccec_const_cp_t ccec_cp_224(void)
{
#if CCN_MULMOD_224_ASM
    return ccec_cp_224_asm();
#else
    return ccec_cp_224_c();
#endif
}
