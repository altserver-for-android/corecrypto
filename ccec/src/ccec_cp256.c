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

#include <corecrypto/cc_runtime_config.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "ccn_internal.h"

// 2^512 mod P.
static const cc_unit RR_MOD_P[CCN256_N] = {
    CCN256_C(00,00,00,04,ff,ff,ff,fd,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fb,ff,ff,ff,ff,00,00,00,00,00,00,00,03)
};

// 2^256 mod P.
static const cc_unit R1_MOD_P[CCN256_N] = {
    CCN256_C(00,00,00,00,ff,ff,ff,fe,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,00,00,00,00,00,00,00,00,00,00,00,01)
};

/*! @function ccn_addmul1_p256
 @abstract Computes r += p256 * v.

 @param r  Result
 @param v  Limb to add

 @return Any carry bits.
 */
CC_NONNULL_ALL
#if (CCN_UNIT_SIZE == 8) && CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0xffffffffffffffff
    tmp = (cc_dunit)r[0] + (((cc_dunit)v << 64) - v);
    r[0] = (cc_unit)tmp;

    // * 0x00000000ffffffff
    tmp = (cc_dunit)r[1] + v1 + (tmp >> 64);
    r[1] = (cc_unit)tmp;

    // * 0x0000000000000000
    tmp = (cc_dunit)r[2] + (tmp >> 64);
    r[2] = (cc_unit)tmp;

    // * 0xffffffff00000001
    tmp = (cc_dunit)r[3] + ((v1 << 32) + v) + (tmp >> 64);
    r[3] = (cc_unit)tmp;

    return (tmp >> 64);
}
#elif (CCN_UNIT_SIZE == 4)
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    cc_dunit tmp;

    // v * 0xffffffff
    cc_dunit v1 = ((cc_dunit)v << 32) - v;

    // * 0xffffffff
    tmp = (cc_dunit)r[0] + v1;
    r[0] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[1] + v1 + (tmp >> 32);
    r[1] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[2] + v1 + (tmp >> 32);
    r[2] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[3] + (tmp >> 32);
    r[3] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[4] + (tmp >> 32);
    r[4] = (cc_unit)tmp;

    // * 0x00000000
    tmp = (cc_dunit)r[5] + (tmp >> 32);
    r[5] = (cc_unit)tmp;

    // * 0x00000001
    tmp = (cc_dunit)r[6] + v + (tmp >> 32);
    r[6] = (cc_unit)tmp;

    // * 0xffffffff
    tmp = (cc_dunit)r[7] + v1 + (tmp >> 32);
    r[7] = (cc_unit)tmp;

    return (tmp >> 32);
}
#else
static cc_unit ccn_addmul1_p256(cc_unit *r, cc_unit v)
{
    return ccn_addmul1(CCN256_N, r, ccec_cp_p(ccec_cp_256()), v);
}
#endif

/*! @function ccn_p256_redc
 @abstract Computes r := t / R (mod p256) via Montgomery's REDC algorithm.

 @param zp  Multiplicative group Z/(p)
 @param r   Result of the reduction
 @param t   Number to reduce
 */
CC_NONNULL_ALL
static void ccn_p256_redc(cczp_const_t zp, cc_unit *r, cc_unit *t)
{
    // m := ((t mod R) * p0inv) mod R
    // t := (t + m * p) / R
    //   where p0inv = -p[0]^(-1) (mod 2^w)
    for (cc_size i = 0; i < CCN256_N; i++) {
        // Write carries to t[i] directly as each iteration of the partial
        // REDC algorithm zeroes the current word t[i]. When finished, the
        // lower half of t contains the carries that are then added to the
        // intermediate result in t's upper half.
        t[i] = ccn_addmul1_p256(&t[i], t[i]);
    }

    // Optional final reduction.
    cc_unit s = ccn_add(CCN256_N, &t[CCN256_N], &t[CCN256_N], t);
    s ^= ccn_sub(CCN256_N, t, &t[CCN256_N], cczp_prime(zp));
    ccn_mux(CCN256_N, s, r, &t[CCN256_N], t);

    /* Sanity check. */
    cc_assert(ccn_cmp(CCN256_N, r, cczp_prime(zp)) < 0);
}

/*! @function ccn_p256_mul_ws
 @abstract Multiplies two 256-bit numbers x and y.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Multiplier
 @param y   Multiplicand
 */
CC_NONNULL_ALL
static void ccn_p256_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y)
{
    cc_size n = CCN256_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_mul_ws(ws, CCN256_N, rbig, x, y);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p256_sqr_ws
 @abstract Squares a 256-bit number x.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result
 @param x   Number to square
 */
CC_NONNULL_ALL
static void ccn_p256_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN256_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_sqr_ws(ws, CCN256_N, rbig, x);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

/*! @function ccn_p256_is_one_ws
 @abstract Returns whether x = R (mod p256), i.e. whether x = 1 in Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Number

 @return True, if x = R (mod p256). False otherwise.
 */
CC_NONNULL_ALL
bool ccn_p256_is_one_ws(CC_UNUSED cc_ws_t ws, CC_UNUSED cczp_const_t zp, const cc_unit *x)
{
    return ccn_cmp(CCN256_N, x, R1_MOD_P) == 0;
}

/*! @function ccn_p256_to_ws
 @abstract Computes r := x * R (mod p256) to convert x to Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
void ccn_p256_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cczp_mul_ws(ws, zp, r, x, RR_MOD_P);
}

/*! @function ccn_p256_from_ws
 @abstract Computes r := x / R (mod p256) to convert x out of Montgomery space.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result not in Montgomery space
 @param x   Number to convert
 */
CC_NONNULL_ALL
static void ccn_p256_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x)
{
    cc_size n = CCN256_N;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *rbig = CC_ALLOC_WS(ws, 2 * n);
    ccn_setn(2 * CCN256_N, rbig, CCN256_N, x);
    ccn_p256_redc(zp, r, rbig);
    CC_FREE_BP_WS(ws, bp);
}

#pragma workspace-override cczp_mul_ws ccn_p256_mul_ws
#pragma workspace-override cczp_sqr_ws ccn_p256_sqr_ws
#pragma workspace-override cczp_is_one_ws ccn_p256_is_one_ws
#pragma workspace-override cczp_to_ws ccn_p256_to_ws
#pragma workspace-override cczp_from_ws ccn_p256_from_ws

static cczp_funcs_decl(cczp_p256_funcs_c,
    ccn_p256_mul_ws,
    ccn_p256_sqr_ws,
    cczp_mod_default_ws,
    cczp_inv_default_ws,
    cczp_sqrt_default_ws,
    ccn_p256_to_ws,
    ccn_p256_from_ws,
    ccn_p256_is_one_ws);

static const ccec_cp_decl(256) ccec_cp256_c =
{
    .hp = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = &cczp_p256_funcs_c
    },
    .p = {
        CCN256_C(ff,ff,ff,ff,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .pr = {
        CCN256_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,fe,ff,ff,ff,fe,ff,ff,ff,ff,00,00,00,00,00,00,00,03),1
    },
    .b = {
        CCN256_C(dc,30,06,1d,04,87,48,34,e5,a2,20,ab,f7,21,2e,d6,ac,f0,05,cd,78,84,30,90,d8,9c,df,62,29,c4,bd,df)
    },
    .gx = {
        CCN256_C(6b,17,d1,f2,e1,2c,42,47,f8,bc,e6,e5,63,a4,40,f2,77,03,7d,81,2d,eb,33,a0,f4,a1,39,45,d8,98,c2,96)
    },
    .gy = {
        CCN256_C(4f,e3,42,e2,fe,1a,7f,9b,8e,e7,eb,4a,7c,0f,9e,16,2b,ce,33,57,6b,31,5e,ce,cb,b6,40,68,37,bf,51,f5)
    },
    .hq = {
        .n = CCN256_N,
        .bitlen = 256,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .q = {
        CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,51)
    },
    .qr = {
        CCN256_C(00,00,00,00,ff,ff,ff,ff,ff,ff,ff,fe,ff,ff,ff,ff,43,19,05,52,df,1a,6c,21,01,2f,fd,85,ee,df,9b,fe),1
    }
};

ccec_const_cp_t ccec_cp_256_c(void)
{
    return (ccec_const_cp_t)&ccec_cp256_c;
}

CC_WEAK_IF_SMALL_CODE
ccec_const_cp_t ccec_cp_256(void)
{
#if CCN_MULMOD_256_ASM
#if defined(__x86_64__)
    if (CC_HAS_BMI2() && CC_HAS_ADX())
#endif
        return ccec_cp_256_asm();
#endif

#if !CCN_MULMOD_256_ASM || defined(__x86_64__)
    return ccec_cp_256_c();
#endif
}
