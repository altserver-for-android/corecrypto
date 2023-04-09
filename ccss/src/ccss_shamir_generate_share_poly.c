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

#include "cc_macros.h"
#include "ccss_shamir_internal.h"
#include <corecrypto/ccss_shamir.h>

int ccss_shamir_generate_share_poly_ws(cc_ws_t ws,
                                       ccss_shamir_share_generator_state_t poly,
                                       struct ccrng_state *rng_state,
                                       size_t secret_nbytes,
                                       const uint8_t *secret,
                                       bool exact_secrets)
{
    int error = CCERR_OK;

    // If exact secrets is not set, ensure secret is at least a byte smaller than prime field.
    if (!ccss_shamir_secret_one_byte_smaller_than_prime(poly->field, secret_nbytes) && !exact_secrets) {
        return CCSS_ELEMENT_TOO_LARGE_FOR_FIELD;
    }

    // Create a random polynomial and then copy *secret to the constant
    // coefficient.
    cc_require((error = ccss_shamir_generate_random_poly_ws(ws, poly, rng_state)) == CCERR_OK, errOut);
    error = ccss_encode_string_into_value_smaller_than_prime(poly->field, poly->coefficients, secret_nbytes, secret);

errOut:
    return error;
}
