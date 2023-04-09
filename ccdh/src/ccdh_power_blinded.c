/* Copyright (c) (2016-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdh.h>
#include "ccdh_internal.h"
#include <corecrypto/cc_priv.h>
#include "cczp_internal.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_memory.h>
#include <corecrypto/cc_workspaces.h>

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MSBIT (((cc_unit)1)<<(SCA_MASK_BITSIZE-1))
#define SCA_MASK_MASK  ((SCA_MASK_MSBIT-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK (SCA_MASK_N * 3)   // base, exponent, modulus

cc_static_assert(SCA_MASK_N == 1, "we use ccn_mul1() for masks");

CC_PURE cc_size CCDH_POWER_BLINDED_WORKSPACE_N(cc_size n)
{
    cc_size nu = n + SCA_MASK_N;
    return n + (2 * nu) + cczp_nof_n(nu) + cczp_mm_nof_n(nu) +
      CC_MAX_EVAL(CCN_DIV_EUCLID_WORKSPACE_N(n, SCA_MASK_N),
        CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(nu, nu),
          CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(nu),
            CC_MAX_EVAL(CCZP_MM_INIT_WORKSPACE_N(nu),
              CC_MAX_EVAL(CCZP_MUL_WORKSPACE_N(nu),
                CC_MAX_EVAL(CCZP_POWER_WORKSPACE_N(nu),
                  CC_MAX_EVAL(CCZP_TO_WORKSPACE_N(nu),
                              CCZP_FROM_WORKSPACE_N(nu))
                )
              )
            )
          )
        )
      );
}

int ccdh_power_blinded_ws(cc_ws_t ws,
                          struct ccrng_state *blinding_rng,
                          ccdh_const_gp_t gp,
                          cc_unit *r,
                          const cc_unit *s,
                          size_t ebitlen,
                          const cc_unit *e)
{
    int status = CCERR_PARAMETER;

    // Allocate a ZP which will be used to extend p for randomization
    cc_size np=ccdh_gp_n(gp);
    cc_size nu=np+SCA_MASK_N;

    // Allocate working memory
    CC_DECL_BP_WS(ws, bp);
    cc_unit e0;
    cc_unit *e1=CC_ALLOC_WS(ws, np);
    cc_unit *s_star=CC_ALLOC_WS(ws, nu);
    cc_unit *tmp=CC_ALLOC_WS(ws, nu);

    cczp_t zu_masked = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(nu));
    cczp_t zpmm = (cczp_t)CC_ALLOC_WS(ws, cczp_mm_nof_n(nu));

    // Enforce parameter bounds.
    cc_require(ccn_nof(ebitlen) <= np, errOut);
    cc_require(ccn_cmp(np, s, ccdh_gp_prime(gp)) < 0, errOut);
    cc_require(ccn_cmpn(ccn_nof(ebitlen), e, np, ccdh_gp_prime(gp)) < 0, errOut);

    // Random for masking. One call to reduce latency
    cc_unit rnd[SCA_MASK_N*NB_MASK];
    cc_require((status=ccn_random(NB_MASK, rnd, blinding_rng))==0,errOut);

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(rnd[0]);

    /*
     Modulus blinding:   p_star = rnd[0]*p
     Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1]
       such that (e1*rnd[1] + e0) == e
     Base blinding:      s_star = (x + rnd[2]*p) mod p_star
     */

    /* Modulus blinding:   p_star = rnd[0]*p */
    CCZP_N(zu_masked)=nu;
    rnd[0] &= SCA_MASK_MASK; // truncate as needed
    rnd[0] |= (SCA_MASK_MSBIT|1); // Odd and big
    *(CCZP_PRIME(zu_masked)+np)=ccn_mul1(np,CCZP_PRIME(zu_masked),ccdh_gp_prime(gp),rnd[0]);
    status = cczp_init_ws(ws, zu_masked);
    cc_require(status == CCERR_OK, errOut);

    /* Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1] */
    rnd[1] &= SCA_MASK_MASK; // truncate as needed
    rnd[1] |= SCA_MASK_MSBIT; // non zero and big
    cc_require((status=ccn_div_euclid_ws(ws, np, e1, SCA_MASK_N, &e0, ccn_nof(ebitlen), e, SCA_MASK_N, &rnd[1]))==0,errOut);

    /* Base blinding:      s_star = (x + rnd[2]*p) mod p_star */
    ccn_set(np,tmp,s);
    rnd[2] &= SCA_MASK_MASK; // truncate as needed
    tmp[np]=ccn_addmul1(np,tmp,ccdh_gp_prime(gp), rnd[2]);    /* tmp = rnd[2] * p */
    cc_require((status=cczp_modn_ws(ws, zu_masked,s_star,nu,tmp))==0,errOut);

    status = cczp_mm_init_ws(ws, zpmm, nu, cczp_prime(zu_masked));
    cc_require(status == CCERR_OK, errOut);
    cczp_to_ws(ws, zpmm, s_star, s_star);

    /* s_star^e1 */
    cc_require((status = cczp_power_ws(ws, zpmm, tmp, s_star, ebitlen - SCA_MASK_BITSIZE + 1, e1)) == CCERR_OK, errOut);

    /* (s_star^e1)^rnd[1] */
    cc_require((status = cczp_power_ws(ws, zpmm, tmp, tmp, SCA_MASK_BITSIZE, &rnd[1])) == CCERR_OK, errOut);

    /* s_star^e0 */
    cc_require((status = cczp_power_ws(ws, zpmm, s_star, s_star, SCA_MASK_BITSIZE, &e0)) == CCERR_OK, errOut);

    /* (s_star^e1)^rnd[1] * s_star^e0 = s_star^e */
    cczp_mul_ws(ws, zpmm, s_star, s_star, tmp);
    cczp_from_ws(ws, zpmm, s_star, s_star);
    status=cczp_modn_ws(ws,ccdh_gp_zp(gp),r,nu,s_star);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return status;
}
