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
#include <corecrypto/ccn.h>
#include <corecrypto/ccss_shamir.h>

const uint8_t CCSS_PRIME_P192[24] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const uint8_t CCSS_PRIME_P224[28] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

const uint8_t CCSS_PRIME_P256[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const uint8_t CCSS_PRIME_P384[48] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

const uint8_t CCSS_PRIME_P521[66] = {
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff
};

size_t ccss_sizeof_generator(const ccss_shamir_parameters_t params)
{
    return sizeof(struct ccss_shamir_share_generator) + ccn_sizeof_n(cczp_n(&params->field)) * params->threshold;
}

size_t ccss_sizeof_share(const ccss_shamir_parameters_t params)
{
    return sizeof(struct ccss_shamir_share) + ccn_sizeof_n(cczp_n(&params->field));
}

size_t ccss_sizeof_parameters(size_t prime_nbytes)
{
    cc_size n = ccn_nof_size(prime_nbytes);
    return sizeof(struct ccss_shamir_parameters) + cczp_payload_sizeof_n(n);
}

size_t ccss_sizeof_share_bag(const ccss_shamir_parameters_t params)
{
    return sizeof(struct ccss_shamir_share_bag) + ccn_sizeof_n(params->threshold * (cczp_n(&params->field) + ccn_nof_size(sizeof(uint32_t))));
}

// Accessor functions for polynomial struct.
// Note the preference is to not access elements directly in the struct unless
// there's a reason.

cc_unit *ccss_shamir_poly_coefficient(ccss_shamir_share_generator_state_t poly,
                                      uint32_t i) {
  if (i > poly->degree) {
    cc_abort("ccss_shamir_poly_coefficient with index bigger than or equal to "
             "threshold");
  }
  return &(poly->coefficients[(poly->field->n * (i))]);
}

cc_size ccss_shamir_poly_n(const ccss_shamir_share_generator_state_t poly) {
  return cczp_n(poly->field);
}

cczp_const_t
ccss_shamir_prime_of(const ccss_shamir_share_generator_state_t poly) {
  return poly->field;
}

void ccss_shamir_share_init(ccss_shamir_share_t share,
                           const ccss_shamir_parameters_t params)
{
    CC_ENSURE_DIT_ENABLED

    share->field = &params->field;
}

int ccss_shamir_consistent_primes(cczp_const_t field_l, cczp_const_t field_r) {
  // The most likely use case will have the same object in field_l and field_r,
  // so for performance we first check for equality by checking if lhs and rhs
  // point to the same object. Otherwise we do a more expensive equality check.
  if (field_r != field_l) {
    if (ccn_cmpn(cczp_n(field_r), cczp_prime(field_r), cczp_n(field_l),
                 cczp_prime(field_l))) {
      return CCSS_FIELD_MISMATCH;
    }
  }
  return CCERR_OK;
}

bool csss_shamir_share_bag_can_recover_secret(
    const ccss_shamir_share_bag_t share_bag) {
    CC_ENSURE_DIT_ENABLED

  return share_bag->share_count >= share_bag->params->threshold;
}

int ccss_shamir_parameters_init(ccss_shamir_parameters_t params,
                                size_t prime_nbytes, const uint8_t *prime,
                                uint32_t threshold)
{
    CC_ENSURE_DIT_ENABLED

    if (threshold < CCSS_SHARE_MINIMUM_THRESHOLD) {
        return CCSS_THRESHOLD_NOT_LARGE_ENOUGH;
    }

    cc_size n = ccn_nof_size(prime_nbytes);

    CCZP_N(&params->field) = n;
    int rv = ccn_read_uint(n, CCZP_PRIME(&params->field), prime_nbytes, prime);
    if (rv) {
        return rv;
    }

    rv = cczp_init(&params->field);
    if (rv) {
        return rv;
    }

    cc_unit threshold_in_unit_rep = (cc_unit)threshold;
    if (ccn_cmpn(1, &threshold_in_unit_rep, n, cczp_prime(&params->field)) >= 0) {
        return CCSS_THRESHOLD_LARGER_OR_EQUAL_TO_FIELD;
    }

    params->threshold = threshold;

    return CCERR_OK;
}

size_t ccss_shamir_parameters_maximum_secret_length(
    const ccss_shamir_parameters_t params) {
    CC_ENSURE_DIT_ENABLED

  return (ccn_sizeof_n(cczp_n(&params->field)) - 1);
}
