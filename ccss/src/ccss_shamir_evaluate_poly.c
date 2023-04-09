/* Copyright (c) (2018,2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccss_shamir_internal.h"
#include <corecrypto/ccss_shamir.h>
#include "cc_workspaces.h"

static void ccss_shamir_evaluate_poly_to_buffer_ws(
    cc_ws_t ws, const ccss_shamir_share_generator_state_t poly, uint32_t x, cc_unit *y)
{
    cczp_const_t field = poly->field;
    cc_size n = field->n;

    CC_DECL_BP_WS(ws, bp);

    cc_unit *xpower = CC_ALLOC_WS(ws, n); // Stores x^i
    cc_unit *xlong = CC_ALLOC_WS(ws, n);  // An n-unit representation of x
    cc_unit *temp = CC_ALLOC_WS(ws, n);   // Temporary value.
    cc_unit *result = CC_ALLOC_WS(ws, n); // Stores the cummulative result of evaluating the poly
    ccn_seti(n, xpower, x);
    ccn_seti(n, xlong, x);

    // Load constant co-efficient into result, as it acts as an accumulator for
    // result.
    ccn_set(n, result, ccss_shamir_poly_coefficient(poly, 0)); // result = c_0

    for (uint32_t i = 1; i <= poly->degree; i++) {
      cczp_mul_ws(ws, field, temp, xpower,
                  ccss_shamir_poly_coefficient(poly, i)); // temp = x^i * c_i
      cczp_add_ws(ws, field, result, temp, result);       // result += x^i*c_i
      cczp_mul_ws(ws, field, xpower, xlong, xpower);      // x^{i+1} = x^i * x
    }

    ccn_setn(n, y, n, result);
    CC_FREE_BP_WS(ws, bp);
}

int ccss_shamir_evaluate_poly_to_buffer(
    const ccss_shamir_share_generator_state_t poly, uint32_t x, cc_unit *y)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSS_SHAMIR_EVALUATE_POLY_TO_BUFFER_WORKSPACE_N(poly->field->n));
    ccss_shamir_evaluate_poly_to_buffer_ws(ws, poly, x, y);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return CCERR_OK;
}
