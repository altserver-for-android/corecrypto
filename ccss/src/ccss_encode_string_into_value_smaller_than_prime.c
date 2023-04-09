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

#include "ccn_internal.h"
#include "ccss_shamir_internal.h"
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccss_shamir.h>
#include <string.h>

int ccss_encode_string_into_value_smaller_than_prime(cczp_const_t field, cc_unit *dest,
                                  size_t string_nbytes, const uint8_t *string) {
  // Make sure that secret fits in the field.
  const cc_size field_n = cczp_n(field);
  cc_unit const *field_prime = cczp_prime(field);
  int error = CCERR_OK;

  // If the secret length <= field length then copy the secret into a ccn
  // buffer so we can use a constant time comparison to ensure it fits.
  error = ccn_read_uint(field_n, dest, string_nbytes, string);
  cc_require(error == CCERR_OK, errout);
  int comparison = ccn_cmp(field_n, dest, field_prime);
  cc_require(comparison < 0, nofiterror);
  return CCERR_OK;
nofiterror:
  error = CCSS_ELEMENT_TOO_LARGE_FOR_FIELD;
errout:
  ccn_clear(field_n, dest);
  return error;
}

bool ccss_shamir_secret_one_byte_smaller_than_prime(cczp_const_t field,
                                          size_t secret_nbytes) {
  // Make sure that prime takes n+1 bytes to represent if secret is n bytes
  size_t poly_prime_nbytes = CC_BITLEN_TO_BYTELEN(cczp_bitlen(field));

  // If secret length is bigger than or equal to field length it doesn't fit
  if (secret_nbytes >= poly_prime_nbytes) {
    return false;
  }

  return true;
}
