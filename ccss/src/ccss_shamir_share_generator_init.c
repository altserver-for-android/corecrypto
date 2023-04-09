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
#include "cc_workspaces.h"

// Share generator initialization function that backs both regular and hazardous initialization.
// It takes a boolean exact_secrets to determine which of the two modes is being called.
// exact_secrets is true if secret can be any value smaller than prime field. Is false if it needs to be
// at least 1 byte smaller than the number of bytes representing the prime defining the field.
static int ccss_shamir_share_generator_init_backer_ws(cc_ws_t ws,
                                                      ccss_shamir_share_generator_state_t state,
                                                      const ccss_shamir_parameters_t params,
                                                      struct ccrng_state *rng_state,
                                                      const uint8_t *secret,
                                                      size_t secret_nbytes,
                                                      bool exact_secrets)
{
    ccss_shamir_init_share_poly(state, params);
    return ccss_shamir_generate_share_poly_ws(ws, state, rng_state, secret_nbytes, secret, exact_secrets);
}

int ccss_shamir_share_generator_init(ccss_shamir_share_generator_state_t state,
                                     const ccss_shamir_parameters_t params,
                                     struct ccrng_state *rng_state,
                                     const uint8_t *secret,
                                     size_t secret_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSS_SHAMIR_SHARE_GENERATOR_INIT_BACKER_WORKSPACE_N(cczp_n(&params->field)));
    int rv = ccss_shamir_share_generator_init_backer_ws(ws, state, params, rng_state, secret, secret_nbytes, false);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}

int ccss_shamir_share_generator_init_with_secrets_less_than_prime(ccss_shamir_share_generator_state_t state,
                                                                  const ccss_shamir_parameters_t params,
                                                                  struct ccrng_state *rng_state,
                                                                  const uint8_t *secret,
                                                                  size_t secret_nbytes)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSS_SHAMIR_SHARE_GENERATOR_INIT_BACKER_WORKSPACE_N(cczp_n(&params->field)));
    int rv = ccss_shamir_share_generator_init_backer_ws(ws, state, params, rng_state, secret, secret_nbytes, true);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rv;
}
