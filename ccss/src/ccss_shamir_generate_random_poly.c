/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"
#include "ccss_shamir_internal.h"
#include "cczp_internal.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccss_shamir.h>
#include <corecrypto/cczp.h>

// Function to generate a random polynonmial. Assumes that there will
// be no secret past at the moment.
int ccss_shamir_generate_random_poly_ws(cc_ws_t ws, ccss_shamir_share_generator_state_t poly, struct ccrng_state *rng)
{
    int error = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    // Generate each coefficient of the polynomial in turn randomly, all
    // coefficients but final one of poly may be 0.
    for (uint32_t i = 0; i < poly->degree; i++) {
        error = cczp_generate_random_element_ws(ws, poly->field, rng, ccss_shamir_poly_coefficient(poly, i));
        cc_require(error == CCERR_OK, errOut);
    }

    error = cczp_generate_non_zero_element_ws(ws, poly->field, rng, ccss_shamir_poly_coefficient(poly, poly->degree));

errOut:
    CC_FREE_BP_WS(ws, bp);
    return error;
}
