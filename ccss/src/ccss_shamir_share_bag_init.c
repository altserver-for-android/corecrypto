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

void ccss_shamir_share_bag_init(ccss_shamir_share_bag_t share_bag,
                                const ccss_shamir_parameters_t params)
{
    CC_ENSURE_DIT_ENABLED

  share_bag->params = params;
  share_bag->share_count = 0;
}
