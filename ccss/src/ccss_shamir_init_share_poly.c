/* Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement
 * (which is contained in the License.txt file distributed with corecrypto) and
 * only to people who accept that license. IMPORTANT:  Any license rights
 * granted to you by Apple Inc. (if any) are limited to internal use within your
 * organization only on devices and computers you own or control, for the sole
 * purpose of verifying the security characteristics and correct functioning of
 * the Apple Software.  You may not, directly or indirectly, redistribute the
 * Apple Software or any portions thereof.
 */

#include "ccss_shamir_internal.h"
#include <corecrypto/ccss_shamir.h>

// We require at a threshold of size at least two to be a sane secret sharing
// scheme.

// Set field and degree variables in poly to values defined
void ccss_shamir_init_share_poly(ccss_shamir_share_generator_state_t poly, const ccss_shamir_parameters_t params)
{
    poly->field = &params->field;
    poly->degree = params->threshold - 1;
}
