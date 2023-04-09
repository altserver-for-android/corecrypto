/* Copyright (c) (2010,2011,2015,2017-2021) Apple Inc. All rights reserved.
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

#if CCN_ADD1_ASM
cc_unit ccn_add1_asm(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) __asm__("_ccn_add1_asm");
#endif

cc_unit ccn_add1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
    CC_ENSURE_DIT_ENABLED

    if (n == 0) {
        return v; // pass the input to the output
    }

#if CCN_ADD1_ASM
    return ccn_add1_asm(n, r, s, v);
#else

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    cc_dunit carry = v;

    for (cc_size i = 0; i < n; i++) {
        carry += s[i];
        r[i] = (cc_unit)carry;
        carry >>= CCN_UNIT_BITS;
    }
#else
    cc_unit carry = ccn_add(1, r, s, &v);

    for (cc_size i = 1; i < n; i++) {
        carry += s[i] & CCN_UNIT_LOWER_HALF_MASK;
        cc_unit lo = carry & CCN_UNIT_LOWER_HALF_MASK;
        carry >>= CCN_UNIT_HALF_BITS;

        carry += s[i] >> CCN_UNIT_HALF_BITS;
        r[i] = (carry << CCN_UNIT_HALF_BITS) | lo;
        carry >>= CCN_UNIT_HALF_BITS;
    }
#endif /* CCN_UINT128_SUPPORT_FOR_64BIT_ARCH */

    return (cc_unit)carry;
#endif /* CCN_ADD1_ASM */
}
