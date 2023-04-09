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
#include "ccss_shamir_internal.h"
#include <corecrypto/cc.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccss_shamir.h>

int ccss_shamir_share_bag_set_ith_share(ccss_shamir_share_bag_t share_bag,
                                        uint32_t index,
                                        const ccss_shamir_share_t share) {
  int error = ccss_shamir_consistent_primes(&share_bag->params->field, share->field);
  if (error != CCERR_OK) {
    return error;
  }
  if (index >= share_bag->params->threshold) {
    return CCSS_INDEX_OUT_OF_RANGE;
  }

  return ccss_shamir_share_bag_set_ith_share_with_xy(share_bag, index, share->x,
                                                     share->y);
}

int ccss_shamir_share_bag_set_ith_share_with_xy(
    ccss_shamir_share_bag_t share_bag, uint32_t index, uint32_t x,
    const cc_unit *y) {
  cc_size field_ccn_size = cczp_n(&share_bag->params->field);

  if (index >= share_bag->params->threshold) {
    return CCSS_INDEX_OUT_OF_RANGE;
  }
  // Set x coordinate
  uint32_t *x_value =
      (void *)&share_bag
          ->shares[index * (field_ccn_size + ccn_nof_size(sizeof(uint32_t)))];
  *x_value = x;

  // Set y coordinate.
  cc_unit *y_value =
      &share_bag
           ->shares[index * (field_ccn_size + ccn_nof_size(sizeof(uint32_t))) +
                    ccn_nof_size(sizeof(uint32_t))];
  ccn_set(cczp_n(&share_bag->params->field), y_value, y);

  return CCERR_OK;
}

uint32_t
ccss_shamir_share_bag_copy_ith_share_x(ccss_shamir_share_bag_t share_bag,
                                       uint32_t index) {
  if (index > share_bag->share_count - 1) {
    cc_abort(
        "Attempt to copy x value of share out of share bag with invalid share "
        "index"); // Such an index can only happen due to programmer error,
  }
  cc_size field_ccn_size = cczp_n(&share_bag->params->field);
  uint32_t *x_value =
      (void *)&share_bag
          ->shares[index * (field_ccn_size + ccn_nof_size(sizeof(uint32_t)))];
  return *x_value;
}

cc_unit *ccss_shamir_share_bag_ith_share_y(ccss_shamir_share_bag_t share_bag,
                                           uint32_t index) {
  if (index > share_bag->share_count - 1) {
    cc_abort("Attempt to access y value of share out of share bag with invalid "
             "share index");
  }
  cc_size field_ccn_size = cczp_n(&share_bag->params->field);
  return &share_bag->shares[index * (field_ccn_size +
                                     ccn_nof_size(sizeof(uint32_t))) +
                            ccn_nof_size(sizeof(uint32_t))];
}

int ccss_shamir_share_import(ccss_shamir_share_t share, uint32_t x,
                             const uint8_t *y, size_t y_nbytes) {
    CC_ENSURE_DIT_ENABLED

  int error =
      ccss_encode_string_into_value_smaller_than_prime(share->field, share->y, y_nbytes, y);
  cc_require(error == CCERR_OK, errOut);
  share->x = x;

errOut:
  return error;
}

size_t ccss_shamir_share_sizeof_y(const ccss_shamir_share_t share) {
    CC_ENSURE_DIT_ENABLED

  return ccn_sizeof_n(cczp_n(share->field));
}

int ccss_shamir_share_export(const ccss_shamir_share_t share, uint32_t *x,
                             uint8_t *y, size_t y_nbytes) {
    CC_ENSURE_DIT_ENABLED


  if (ccn_write_uint_size(cczp_n(share->field), share->y) > y_nbytes) {
    return CCERR_PARAMETER;
  }

  ccn_write_uint_padded_ct(cczp_n(share->field), share->y, y_nbytes, y);
  *x = share->x;
  return CCERR_OK;
}
