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
#include <corecrypto/ccss_shamir.h>

int ccss_shamir_share_bag_add_share(ccss_shamir_share_bag_t share_bag,
                                    const ccss_shamir_share_t share) {
    CC_ENSURE_DIT_ENABLED

  if (share_bag->share_count >= share_bag->params->threshold) {
    return CCSS_SHARE_BAG_FULL;
  }

  // Iterate through and see if the current share is already in the share bag.
  // Not constant time, but unless keeping the number of shares retrieved needs
  // to be kept a secret there shouldn't be a need a reason for it to be.
  for (uint32_t i = 0; i < share_bag->share_count; i++) {
    if (share->x == ccss_shamir_share_bag_copy_ith_share_x(share_bag, i)) {
      return CCSS_SHARE_ALREADY_PRESENT_IN_SHARE_BAG;
    }
  }

  // Add share to the share bag.
  int error = ccss_shamir_share_bag_set_ith_share(
      share_bag, share_bag->share_count, share);
  if (error == CCERR_OK) {
    share_bag->share_count++;
  }

  return error;
}
