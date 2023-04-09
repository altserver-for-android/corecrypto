/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include "ccss_shamir_internal.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccss_shamir.h>

int ccss_shamir_share_generator_generate_share(
    const ccss_shamir_share_generator_state_t poly, uint32_t index,
    ccss_shamir_share_t share) {
    CC_ENSURE_DIT_ENABLED

  if (index == 0) {
    // Test to make sure we are not return the share that has the secret as its
    // coefficient.
    // We should never return this share. All **security is lost** at that
    // point.
    return CCSS_INDEX_OUT_OF_RANGE;
  }
  int error = ccss_shamir_consistent_primes(poly->field, share->field);
  cc_require(error == CCERR_OK, errOut);

  // Ensure that the prime of the field is larger than the number of shares
  // requested. Shamir Secret sharing is not correct if the shares are not on
  // unique points. Note this is only an issue with small primes.
  cc_unit number_in_unit_rep = (cc_unit)index;
  if (ccn_cmpn(1, &number_in_unit_rep, cczp_n(ccss_shamir_prime_of(poly)),
               cczp_prime(ccss_shamir_prime_of(poly))) >= 0) {
    return CCSS_INDEX_OUT_OF_RANGE;
  }

  ccss_shamir_evaluate_poly_to_buffer(poly, index, share->y);
  share->x = index;

errOut:
  return error;
}
