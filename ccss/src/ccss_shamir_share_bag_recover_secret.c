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

#include "cc_internal.h"
#include "ccn_internal.h"
#include "ccss_shamir_internal.h"
#include "cczp_internal.h"
#include <corecrypto/ccss_shamir.h>
#include <corecrypto/cczp.h>

// The following function computes the constant co-efficient for reconstructed
// lagrange polynomials. It computes
// (-1)^{degree}\prod_{i=0}^degree x_i=z.
// This is useful because the jth legrange polynomial p_j is only evaluated on
// p_j(0), and therefore only the constant value of the polynomial is needed.
// Its value is z/x_j.
static int ccss_shamir_lagrange_product_from_bag_ws(
    cc_ws_t ws, ccss_shamir_share_bag_t share_bag, cc_unit *accumulator)
{
  uint32_t degree = share_bag->params->threshold - 1;
  if (degree == 0) {
    return CCSS_IMPROPER_DEGREE;
  }

  if (!csss_shamir_share_bag_can_recover_secret(share_bag)) {
    return CCSS_NOT_ENOUGH_SHARES;
  }

  cczp_const_t field = &share_bag->params->field;
  cc_size n = cczp_n(field);

  // Create a workspace
  CC_DECL_BP_WS(ws, bp);
  cc_unit *current = CC_ALLOC_WS(ws, n);

  // Accumulator stores product so far, which is initially x_0
  ccn_seti(n, accumulator,
           ccss_shamir_share_bag_copy_ith_share_x(share_bag, 0));

  // Multiply by x_1.x_2....x_{degree}
  for (uint32_t i = 1; i <= degree; i++) {
    ccn_seti(n, current, ccss_shamir_share_bag_copy_ith_share_x(share_bag, i));
    cczp_mul_ws(ws, field, accumulator, accumulator, current);
  }

  // Multiply by -1^{degree}. Note (degree mod 2) = degree & 0x1
  if (degree & 0x1) {
    cczp_negate(field, accumulator, accumulator);
  }

  CC_FREE_BP_WS(ws, bp);
  return CCERR_OK;
}

// This function recovers the shared secret given n points taken from a
// polynomial P(x) of degree d. This algorithm uses the first d points (n>=d)
// {(x_1,y_1),...,(x_d,y_d)} and reconstructs P(0) which is the shared secret as
// follows. Compute \Sum_{i=1}^d (y_i(z/(x_i*w_i))) where  1) z = (-1)^d
// \prod_{i=1}^d x_i and    2) w_i = \prod_{j\neq i} (x_i-x_j) We use y_j to
// represent x_i-x_j
static int ccss_shamir_share_bag_recover_secret_ws(cc_ws_t ws,
                                                   const ccss_shamir_share_bag_t share_bag,
                                                   uint8_t *result, size_t result_nbytes)
{
  if (share_bag->share_count < share_bag->params->threshold) {
    return CCSS_NOT_ENOUGH_SHARES;
  }

  uint32_t threshold = share_bag->params->threshold;
  cczp_const_t field = &share_bag->params->field;
  cc_size n = cczp_n(field);

  int error = CCERR_OK;
  // Make some place to store computing variables
  CC_DECL_BP_WS(ws, bp);
  cc_unit *z = CC_ALLOC_WS(ws, n);
  cc_unit *w_i = CC_ALLOC_WS(ws, n);
  cc_unit *accum = CC_ALLOC_WS(ws, n);
  cc_unit *x_i = CC_ALLOC_WS(ws, n);
  cc_unit *y_j = CC_ALLOC_WS(ws, n);
  cc_unit *tmp_result = CC_ALLOC_WS(ws, n);

  // Compute product Z of first degree values of $x_i$ to save on compute time.
  ccn_seti(n, tmp_result, 0);
  ccss_shamir_lagrange_product_from_bag_ws(ws, share_bag, z);

  for (uint32_t i = 0; i < threshold; i++) {
    uint32_t share_i_x = ccss_shamir_share_bag_copy_ith_share_x(share_bag, i);
    const cc_unit *share_i_y = ccss_shamir_share_bag_ith_share_y(share_bag, i);
    ccn_seti(n, w_i, 1);
    for (uint32_t j = 0; j < threshold; j++) {
      // Note that x's are not secret values
      uint32_t share_j_x = ccss_shamir_share_bag_copy_ith_share_x(share_bag, j);

      if (share_i_x > share_j_x) {
        ccn_seti(n, y_j, share_i_x - share_j_x);
      } else if (share_i_x < share_j_x) {
        ccn_sub1(n, y_j, cczp_prime(field), share_j_x - share_i_x);
      } else {
        if (i != j) {
          error =
              CCSS_TWO_SHARES_FOR_SAME_X; // Same share is in the array twice.
          goto errOut;
        }
        continue;
      }
      cczp_mul_ws(ws, field, w_i, w_i, y_j);
    }

    ccn_seti(n, x_i, share_i_x);            // Get large x_i representation
    cczp_mul_ws(ws, field, x_i, w_i, x_i);  //  x_i.w_i
    cczp_inv_ws(ws, field, w_i, x_i);       // 1/ (x_i . w_i)
    cczp_mul_ws(ws, field, accum, z, w_i);  // accum = z / (x_i.w_i)
    cczp_mul_ws(ws, field, accum, accum,
                share_i_y); // accum = (y_i . z) / (x_i . w_i)
    cczp_add_ws(ws, field, tmp_result, tmp_result, accum); // result += accum
  }

  error = ccn_write_uint_padded_ct(n, tmp_result, result_nbytes, result);
  error = error < 0 ? error : CCERR_OK;  // padded_ct returns posn of first non-zero byte if successful
errOut:
  CC_FREE_BP_WS(ws, bp);
  return error;
}

int ccss_shamir_share_bag_recover_secret(const ccss_shamir_share_bag_t share_bag,
                                         uint8_t *result, size_t result_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    cczp_const_t field = &share_bag->params->field;
    cc_size n = cczp_n(field);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSS_SHAMIR_SHARE_BAG_RECOVER_SECRET_WORKSPACE_N(n));
    int rv = ccss_shamir_share_bag_recover_secret_ws(ws, share_bag, result, result_nbytes);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
