/* Copyright (c) (2012,2015-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>
#include <corecrypto/cczp.h>
#include "cczp_internal.h"

CC_PURE cc_size CCZ_EXPMOD_WORKSPACE_N(cc_size n, cc_size nm)
{
    return cczp_nof_n(n) +
      CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(n),
        CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(nm, n),
                    CCZP_POWER_WORKSPACE_N(n))
      );
}

int ccz_expmod(ccz *r, const ccz *s, const ccz *t, const ccz *u)
{
    CC_ENSURE_DIT_ENABLED

    int status=-1;
    assert(r != s); // actually I think this *is* allowed.
    assert(r != t); // actually I think this *is* allowed.

    cc_size nu = ccz_n(u);
    ccz_set_capacity(r, nu);

    ccz tmp;
    const ccz *m;
    ccz_init(s->isa, &tmp);

    if (ccz_cmp(s, u) >= 0) {
        ccz_mod(&tmp, s, u);
        ccz_set_capacity(&tmp, ccz_n(u));
        ccn_zero(ccz_capacity(&tmp)-ccz_n(u), tmp.u + ccz_n(u));
        m = &tmp;
    } else if (ccz_n(s) < ccz_n(u)) {
        ccz_set(&tmp, s);
        ccz_set_capacity(&tmp, ccz_n(u));
        ccn_zero(ccz_capacity(&tmp)-ccz_n(s), tmp.u + ccz_n(s));
        m = &tmp;
    } else {
        m = s;
    }

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZ_EXPMOD_WORKSPACE_N(nu, m->n));
    CC_DECL_BP_WS(ws, bp);

    cczp_t zu = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(nu));
    CCZP_N(zu) = nu;
    ccn_set(nu, CCZP_PRIME(zu), u->u);

    cczp_init_ws(ws, zu);

    size_t tbits = ccz_bitlen(t);
    ccz_set_capacity(&tmp, ccz_n(m));
    status = cczp_modn_ws(ws, zu, tmp.u, m->n, m->u);
    status |= cczp_power_ws(ws, zu, r->u, tmp.u, tbits, t->u);

    ccz_set_n(r, ccn_n(cczp_n(zu), r->u));
    ccz_free(&tmp);

    CC_FREE_BP_WS(ws, bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);

    return status;
}
