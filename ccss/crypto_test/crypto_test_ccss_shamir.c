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

#include "ccprime_internal.h"
#include "ccss_shamir_internal.h"
#include "cczp_internal.h"
#include "crypto_test_ccss_shamir.h"
#include "testmore.h"
#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccss_shamir.h>
#include <corecrypto/cczp.h>
#include <limits.h>
#include <stdlib.h>

#ifdef CCSS_TEST_DEBUG
// Function for debugging which prints base prime and coefficients of a
// polynonmial.
static void ccss_shamir_print_poly(ccss_shamir_share_generator_state_t poly) {
  printf("Polynomial\n");
  printf("Degree %d\n", poly->degree);
  cc_print("Base Prime", ccn_sizeof_n(poly->field->n),
           (const uint8_t *)poly->field->ccn);
  for (uint32_t i = 0; i <= poly->degree; i++) {
    printf("Coefficient %d is:\n", i);
    cc_print("Co", ccn_sizeof_n(poly->field->n),
             (uint8_t *)ccss_shamir_poly_coefficient(poly, i));
  }
}

// Function which prints shares in a share bag.
static void ccss_shamir_print_share_bag(ccss_shamir_share_bag_t share_bag) {
  printf("Shares\n");
  cc_print("Base Prime", ccn_sizeof_n(share_bag->field->n),
           (const uint8_t *)share_bag->field->ccn);
  for (uint32_t i = 0; i < share_bag->share_count; i++) {
    printf("Share %zu, x values is %u \t Y coordinate is: ", (size_t)i,
           ccss_shamir_share_bag_get_ith_share_x(share_bag, i));
    cc_print("Y:", ccn_sizeof_n(share_bag->field->n),
             (uint8_t *)ccss_shamir_share_bag_get_ith_share_y(share_bag, i));
  }
}
#endif // CCSS_TEST_DEBUG

// The following function provides an example of how one should generate shares
// and recover a secret
static int ccss_shamir_basic_correctness_test(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  int error = CCERR_OK;
  struct ccrng_state *rng_state = ccrng(&error);
  uint8_t sec[31] = { 0 };

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);
  uint8_t *result_string =
      malloc(ccss_shamir_parameters_maximum_secret_length(params));
  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed to initialize share generator");

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);

  // Generate a threshold number of shares, and store them in the share bag.
  for (uint32_t i = 1; i <= threshold; i++) {
    is(ccss_shamir_share_generator_generate_share(gen_state, i, share),
       CCERR_OK, "Failed to generate share");
    is(ccss_shamir_share_bag_add_share(share_bag, share), CCERR_OK,
       "Failed to add share to share bag");
  }

  // Recover the secret & verify that it matches the input secret
  is(ccss_shamir_share_bag_recover_secret(share_bag, result_string,
                                          ccss_shamir_parameters_maximum_secret_length(params)),
     CCERR_OK, "failed in basic correctness test during recovery");
  ok_memcmp(sec, result_string, sizeof(sec),
            "Shamir Secret Creation and Recovery Failed in basic correctness "
            "test recovered secret does not match original:");

  // Clear up memory
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  free(result_string);
  return CCERR_OK;
}

// The following function provides an example of how one should generate shares
// and recover a secret with the generator that allows the secret to be any value strictly less than the prime.
static int ccss_shamir_basic_ccss_shamir_share_generator_init_with_secrets_less_than_prime_correctness_test(void)
{
    uint32_t threshold = 30;

    // Create random number generator for call to Shamir secret sharing
    int error = CCERR_OK;
    struct ccrng_state *rng_state = ccrng(&error);
    uint8_t sec[31] = { 0 };

    // Create parameters
    ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
    is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold),
       CCERR_OK,
       "Failed to initialize parameters");

    // Create a share to store generated shares temporary
    ccss_shamir_share_decl(share, params);
    ccss_shamir_share_init(share, params);
    uint8_t *result_string = malloc(ccss_shamir_parameters_maximum_secret_length(params));
    // Create a share generator with specified secret
    ccss_shamir_share_generator_decl(gen_state, params);
    is(ccss_shamir_share_generator_init_with_secrets_less_than_prime(gen_state, params, rng_state, sec, sizeof(sec)),
       CCERR_OK,
       "Failed to initialize share generator");

    // Create a share bag, to store shares for reconstruction
    ccss_shamir_share_bag_decl(share_bag, params);
    ccss_shamir_share_bag_init(share_bag, params);

    // Generate a threshold number of shares, and store them in the share bag.
    for (uint32_t i = 1; i <= threshold; i++) {
        is(ccss_shamir_share_generator_generate_share(gen_state, i, share), CCERR_OK, "Failed to generate share");
        is(ccss_shamir_share_bag_add_share(share_bag, share), CCERR_OK, "Failed to add share to share bag");
    }

    // Recover the secret & verify that it matches the input secret
    is(ccss_shamir_share_bag_recover_secret(share_bag, result_string, ccss_shamir_parameters_maximum_secret_length(params)),
       CCERR_OK,
       "failed in basic correctness test during recovery");
    ok_memcmp(sec,
              result_string,
              sizeof(sec),
              "Shamir Secret Creation and Recovery Failed in basic correctness "
              "test recovered secret does not match original:");

    // Clear up memory
    ccss_shamir_share_clear(share, params);
    ccss_shamir_share_bag_clear(share_bag, params);
    ccss_shamir_share_generator_clear(gen_state, params);
    ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
    free(result_string);
    return CCERR_OK;
}

static int ccss_shamir_basic_internal_tests(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  int error = CCERR_OK;
  struct ccrng_state *rng_state = ccrng(&error);

  uint8_t sec[] = {2, 3, 4, 5};

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);
  uint8_t *result_string =
      malloc(ccss_shamir_parameters_maximum_secret_length(params));
  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed to initialize share generator");
  is(ccss_shamir_poly_n(gen_state), ccn_nof_sizeof(CCSS_PRIME_P256),
     "Returning wrong cc_unit size for prime associated with generator");

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);

  // Generate a threshold number of shares, and store them in the share bag.
  for (uint32_t i = 1; i <= threshold; i++) {
    is(ccss_shamir_share_generator_generate_share(gen_state, i, share),
       CCERR_OK, "Failed to generate share");
    is(ccss_shamir_share_bag_add_share(share_bag, share), CCERR_OK,
       "Failed to add share to share bag");
  }
  is(ccss_shamir_share_generator_generate_share(gen_state, threshold + 1,
                                                share),
     CCERR_OK, "Failed to generate share");
  is(ccss_shamir_share_bag_add_share(share_bag, share), CCSS_SHARE_BAG_FULL,
     "Failed to recognize share bag is full");

  // Recover the secret & verify that it matches the input secret
  is(ccss_shamir_share_bag_recover_secret(share_bag, result_string,
                                          ccss_shamir_parameters_maximum_secret_length(params)),
     CCERR_OK, "failed in basic correctness test during recovery");
  ok_memcmp(sec, result_string + ccss_shamir_parameters_maximum_secret_length(params) -sizeof(sec)    , sizeof(sec),
            "Shamir Secret Creation and Recovery Failed in basic correctness "
            "test recovered secret does not match original:");
  is(ccss_shamir_share_bag_set_ith_share(share_bag, threshold + 1, share),
     CCSS_INDEX_OUT_OF_RANGE,
     "failed to detect out of range share index in "
     "ccss_shamir_share_bag_set_ith_share");
  is(ccss_shamir_share_bag_set_ith_share_with_xy(share_bag, threshold + 1,
                                                 share->x, share->y),
     CCSS_INDEX_OUT_OF_RANGE,
     "failed to detect ouf of range share index in "
     "ccss_shamir_share_bag_set_ith_share_with_xy");

  uint32_t dummy_x;
  uint8_t dummy_y;
  is(ccss_shamir_share_export(share, &dummy_x, &dummy_y, 1), CCERR_PARAMETER,
     "Failed to detect that y is not large enough to hold value");

  // Clear up memory
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  free(result_string);
  return CCERR_OK;
}

static int ccss_shamir_basic_internal_test_with_leading_zeros(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  int error = CCERR_OK;
  struct ccrng_state *rng_state = ccrng(&error);

  uint8_t sec[31];
  for (uint8_t i = 0; i < 31; i++){
    sec[i] = i;
  }

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);
  uint8_t *result_string =
      malloc(ccss_shamir_parameters_maximum_secret_length(params));
  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed to initialize share generator");
  is(ccss_shamir_poly_n(gen_state), ccn_nof_sizeof(CCSS_PRIME_P256),
     "Returning wrong cc_unit size for prime associated with generator");

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);

  // Generate a threshold number of shares, and store them in the share bag.
  for (uint32_t i = 1; i <= threshold; i++) {
    is(ccss_shamir_share_generator_generate_share(gen_state, i, share),
       CCERR_OK, "Failed to generate share");
    is(ccss_shamir_share_bag_add_share(share_bag, share), CCERR_OK,
       "Failed to add share to share bag");
  }
  is(ccss_shamir_share_generator_generate_share(gen_state, threshold + 1,
                                                share),
     CCERR_OK, "Failed to generate share");
  is(ccss_shamir_share_bag_add_share(share_bag, share), CCSS_SHARE_BAG_FULL,
     "Failed to recognize share bag is full");

  // Recover the secret & verify that it matches the input secret
  is(ccss_shamir_share_bag_recover_secret(share_bag, result_string,
                                         ccss_shamir_parameters_maximum_secret_length(params)),
     CCERR_OK, "failed in basic correctness test during recovery");
  ok_memcmp(sec, result_string, sizeof(sec),
            "Shamir Secret Creation and Recovery Failed in basic correctness "
            "test recovered secret does not match original:");
  is(ccss_shamir_share_bag_set_ith_share(share_bag, threshold + 1, share),
     CCSS_INDEX_OUT_OF_RANGE,
     "failed to detect out of range share index in "
     "ccss_shamir_share_bag_set_ith_share");
  is(ccss_shamir_share_bag_set_ith_share_with_xy(share_bag, threshold + 1,
                                                 share->x, share->y),
     CCSS_INDEX_OUT_OF_RANGE,
     "failed to detect ouf of range share index in "
     "ccss_shamir_share_bag_set_ith_share_with_xy");

  uint32_t dummy_x;
  uint8_t dummy_y;
  is(ccss_shamir_share_export(share, &dummy_x, &dummy_y, 1), CCERR_PARAMETER,
     "Failed to detect that y is not large enough to hold value");

  // Clear up memory
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  free(result_string);
  return CCERR_OK;
}


static int ccss_shamir_shares_out_of_bounds_test(void) {
  uint32_t threshold = 30;
  const uint8_t prime[] = { 0x01, 0x01 };

  // Create random number generator for call to Shamir secret sharing
  struct ccrng_state *rng_state = global_test_rng;

  uint8_t sec[] = {2};

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(prime));
  is(ccss_shamir_parameters_init(params, sizeof(prime), prime, threshold), CCERR_OK,
     "Failed to initialize share parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);

  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed to initialize share generator");

  is(ccss_shamir_share_generator_generate_share(gen_state, 0, share),
     CCSS_INDEX_OUT_OF_RANGE,
     "Failed to stop request of share corresponding to secret");
  is(ccss_shamir_share_generator_generate_share(gen_state, 257, share),
     CCSS_INDEX_OUT_OF_RANGE,
     "Failed to stop request of share corresponding to secret");

  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(prime));

  return CCERR_OK;
}

static int ccss_shamir_shares_secret_too_big_test(void)
{
    uint32_t threshold = 30;
    const uint8_t prime[] = { 0x01, 0x01 };

    // Create random number generator for call to Shamir secret sharing
    struct ccrng_state *rng_state = global_test_rng;

    uint8_t sec[] = { 1, 0 };

    // Create parameters
    ccss_shamir_parameters_decl(params, sizeof(prime));
    is(ccss_shamir_parameters_init(params, sizeof(prime), prime, threshold), CCERR_OK, "Failed to initialize share parameters");

    // Create a share generator with specified secret
    ccss_shamir_share_generator_decl(gen_state, params);
    is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec, sizeof(sec)),
       CCSS_ELEMENT_TOO_LARGE_FOR_FIELD,
       "Failed to prevent a secret too big for the field from initializing the "
       "generator");
    is(ccss_shamir_share_generator_init_with_secrets_less_than_prime(gen_state, params, rng_state, sec, sizeof(sec)),
       CCERR_OK,
       "Failed to allow a secret one byte smaller than needed to represent prime defining the field from initializing the "
       " hazardous generator");

    is(ccss_shamir_share_generator_init_with_secrets_less_than_prime(gen_state, params, rng_state, prime, sizeof(sec)),
       CCSS_ELEMENT_TOO_LARGE_FOR_FIELD,
       "Failed to prevent a secret equal to  prime from initializing the "
       " hazardous generator");

    sec[0] = 255;
    is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec, 1),
       CCERR_OK,
       "Failed to allow a secret 1 byte smaller than needed to represent prime defining the field from initializing "
       "the generator");

    ccss_shamir_share_generator_clear(gen_state, params);
    ccss_shamir_parameters_clear(params, sizeof(prime));

    return CCERR_OK;
}

static int ccss_shamir_threshold_too_small_test(void)
{
  uint32_t threshold = 1;

  // Create parameters with bogus threshold
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold),
     CCSS_THRESHOLD_NOT_LARGE_ENOUGH,
     "Failed to detect threshold size smaller than 2");

  // create parameters with legit threshold
  threshold = 2;
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Error initializing share parameters");

  return CCERR_OK;
}

static int ccss_shamir_bag_not_full_test(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  struct ccrng_state *rng_state = global_test_rng;
  uint8_t sec[] = {2, 3, 4, 5};

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize share parameters");

  uint8_t *result_string =
      malloc(ccss_shamir_parameters_maximum_secret_length(params));

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);

  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                   sizeof(sec));

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);

  // Generate a threshold number of shares, and store them in the share bag.
  for (uint32_t i = 1; i < threshold; i++) {
    ccss_shamir_share_generator_generate_share(gen_state, i, share);
    ccss_shamir_share_bag_add_share(share_bag, share);
  }

  // Recover the secret & verify that it matches the input secret
  is(ccss_shamir_share_bag_recover_secret(share_bag, result_string,
                                          sizeof(CCSS_PRIME_P256)),
     CCSS_NOT_ENOUGH_SHARES,
     "Failed to detect not having met threshold number of shares in share bag");

  // Clear up memory
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  free(result_string);

  return CCERR_OK;
}

static int ccss_shamir_conflicting_share_test(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  struct ccrng_state *rng_state = global_test_rng;

  uint8_t sec[] = {2, 3, 4, 5};

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize parameters");

  ccss_shamir_parameters_decl(params2, sizeof(CCSS_PRIME_P192));
  is(ccss_shamir_parameters_init(params2, sizeof(CCSS_PRIME_P192), CCSS_PRIME_P192, threshold), CCERR_OK,
     "Failed to initialize parameters");
  ccss_shamir_parameters_decl(params3, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params3, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to initialize parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_init(share, params);

  ccss_shamir_share_decl(share2, params2);
  ccss_shamir_share_init(share2, params2);

  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed initialize generator");
  ccss_shamir_share_generator_decl(gen_state2, params2);
  is(ccss_shamir_share_generator_init(gen_state2, params2, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed initialize generator");

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);
  ccss_shamir_share_bag_decl(share_bag3, params3);
  ccss_shamir_share_bag_init(share_bag3, params3);

  // Generate a share, and store it in the wrong bag.
  is(ccss_shamir_share_generator_generate_share(gen_state2, 1, share),
     CCSS_FIELD_MISMATCH,
     "Failed to catch mismatched filed on copy_out_index_share");
  is(ccss_shamir_share_bag_add_share(share_bag, share), CCERR_OK,
     "Failed to properly add share with same param attribute as share bag");
  is(ccss_shamir_share_bag_add_share(share_bag3, share), CCERR_OK,
     "Failed to properly add share with same valued param attribute as share "
     "bag");
  is(ccss_shamir_share_bag_add_share(share_bag, share),
     CCSS_SHARE_ALREADY_PRESENT_IN_SHARE_BAG,
     "Failed to detect duplicate share in bag");

  ccss_shamir_share_generator_generate_share(gen_state2, 1, share2);
  is(ccss_shamir_share_bag_add_share(share_bag, share2), CCSS_FIELD_MISMATCH,
     "Failed to catch mismatched fields on share insert into a share bag.");

  // Clear up memory
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_bag_clear(share_bag3, params3);
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_clear(share2, params2);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_share_generator_clear(gen_state2, params2);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  ccss_shamir_parameters_clear(params2, sizeof(CCSS_PRIME_P192));
  ccss_shamir_parameters_clear(params3, sizeof(CCSS_PRIME_P256));

  return CCERR_OK;
}

static int ccss_shamir_threshold_bigger_than_field_test(void) {
  const uint8_t small_prime[] = { 13 };
  uint32_t threshold = 13;

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(small_prime));
  is(ccss_shamir_parameters_init(params, sizeof(small_prime), small_prime, threshold),
     CCSS_THRESHOLD_LARGER_OR_EQUAL_TO_FIELD,
     "Allowed initialization where threshold was equal or greater than field "
     "length");
  threshold = 12;
  is(ccss_shamir_parameters_init(params, sizeof(small_prime), small_prime, threshold), CCERR_OK,
     "failed to initialize legitimate parameters");
  params->threshold = 13; // Create illegitimate sate for next test.
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);
  params->threshold = 12; // fix state
  // Clear up memory
  ccss_shamir_share_bag_init(share_bag, params);

  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_parameters_clear(params, sizeof(small_prime));

  return CCERR_OK;
}

static int ccss_shamir_basic_import_export_test(void) {
  uint32_t threshold = 30;

  // Create random number generator for call to Shamir secret sharing
  struct ccrng_state *rng_state = global_test_rng;

  uint8_t sec[31];
  for (uint8_t i = 0; i < 31; i++){
        sec[i] = i;
  }
  uint8_t *result_string = malloc(sizeof(CCSS_PRIME_P256));

  // Create parameters
  ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
  is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
     "Failed to intalize parameters");

  // Create a share to store generated shares temporary
  ccss_shamir_share_decl(share, params);
  ccss_shamir_share_decl(share2, params);
  ccss_shamir_share_init(share, params);
  ccss_shamir_share_init(share2, params);

  // Create a share generator with specified secret
  ccss_shamir_share_generator_decl(gen_state, params);
  is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec,
                                      sizeof(sec)),
     CCERR_OK, "Failed to initialize generator");

  // Create a share bag, to store shares for reconstruction
  ccss_shamir_share_bag_decl(share_bag, params);
  ccss_shamir_share_bag_init(share_bag, params);

  uint8_t y_share_value[ccss_shamir_share_sizeof_y(share)];
  uint32_t x_share_value;

  // Generate a threshold number of shares, and store them in the share bag.
  for (uint32_t i = 1; i <= threshold; i++) {
    ccss_shamir_share_generator_generate_share(gen_state, i, share);

    is(ccss_shamir_share_export(share, &x_share_value, y_share_value,
                                ccss_shamir_share_sizeof_y(share)),
       CCERR_OK, "Failed to export share correctly");
    is(ccss_shamir_share_import(share2, x_share_value, y_share_value,
                                ccss_shamir_share_sizeof_y(share)),
       CCERR_OK, "Failed to import share correctly");

    is(share->x == share2->x, true, "Failed to have matching export/import on x value");
    ok_memcmp(share->y, share2->y, sizeof(cc_unit)*share->field->n, "Failed to have matching export/import on y value");
    is(ccss_shamir_share_bag_add_share(share_bag, share2), CCERR_OK,
       "Failed to add share to bag correctly");
  }

  // Recover the secret & verify that it matches the input secret
  is(ccss_shamir_share_bag_recover_secret(share_bag, result_string,
                                          ccss_shamir_parameters_maximum_secret_length(params)),
     CCERR_OK, "failed in basic correctness test during recovery");
  ok_memcmp(sec, result_string, sizeof(sec),
            "Shamir Secret Creation and Recovery Failed in basic correctness "
            "test recovered secret does not match original:");

  // Clear up memory
  ccss_shamir_share_clear(share, params);
  ccss_shamir_share_clear(share2, params);
  ccss_shamir_share_bag_clear(share_bag, params);
  ccss_shamir_share_generator_clear(gen_state, params);
  ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
  free(result_string);

  return CCERR_OK;
}

static void ccss_shamir_string_into_field_test()
{
  cc_unit p256_prime[] = {0xD};
  cc_size number_of_units_in_prime = CC_ARRAY_LEN(p256_prime);

  // create p256 prime for use as field for Shamir secrets
  cczp_decl_n(number_of_units_in_prime, prime);
  CCZP_N(prime) = number_of_units_in_prime;
  ccn_set(number_of_units_in_prime, CCZP_PRIME(prime), p256_prime);
  is(cczp_init(prime), CCERR_OK, "prime failed to initialize");

  cc_unit hold[number_of_units_in_prime];

  uint8_t too_big_string[] = {0xFF, 0xFF};
  is(ccss_encode_string_into_value_smaller_than_prime(prime, hold, CC_ARRAY_LEN(too_big_string),
                                   too_big_string),
     CCSS_ELEMENT_TOO_LARGE_FOR_FIELD,
     "failed to detect string too large for field");

  uint8_t too_big_string2[] = {0xD};
  is(ccss_encode_string_into_value_smaller_than_prime(prime, hold, CC_ARRAY_LEN(too_big_string2),
                                   too_big_string2),
     CCSS_ELEMENT_TOO_LARGE_FOR_FIELD,
     "failed to detect string too large for field");

  uint8_t ok_string[] = {0xC};
  is(ccss_encode_string_into_value_smaller_than_prime(prime, hold, CC_ARRAY_LEN(ok_string),
                                   ok_string),
     CCERR_OK, "failed to detect string ok for field");
}

static void ccss_shamir_basic_serialization_test()
{
    uint32_t threshold = 30;
 
    // Create random number generator for call to Shamir secret sharing
    int error = CCERR_OK;
    struct ccrng_state *rng_state = ccrng(&error);
    uint8_t sec[31] = { 0 };

    // Create parameters
    ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
    is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
       "Failed to intalize parameters");
    
    // Create a share to store generated shares temporary
    ccss_shamir_share_decl(share, params);
    ccss_shamir_share_init(share, params);
    ccss_shamir_share_decl(share2, params);
    ccss_shamir_share_init(share2, params);
    
    uint8_t *result_string = malloc(ccss_shamir_parameters_maximum_secret_length(params));
    // Create a share generator with specified secret
    ccss_shamir_share_generator_decl(gen_state, params);
    is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec, sizeof(sec)),
       CCERR_OK,
       "Failed to initialize share generator");

    // Create a share bag, to store shares for reconstruction
    ccss_shamir_share_bag_decl(share_bag, params);
    ccss_shamir_share_bag_init(share_bag, params);
    
    // Serialize the generator.
    size_t n;
    is(ccss_sizeof_shamir_share_generator_serialization(gen_state, &n), true, "Error with overflow in calculating ccss_sizeof_shamir_share_generator_serialization");
    uint8_t *data = malloc(n);
    is(ccss_shamir_share_generator_serialize(n, data, gen_state), CCERR_OK, "Error Serializing generator object");

    // Deserialize the generator and create a new one.
    ccss_shamir_share_generator_decl(gen_state_copy, params);

    is(ccss_shamir_share_generator_deserialize(gen_state_copy, params, n, data),
       CCERR_OK,
       "Error deserializing generator object");
    is(gen_state->degree, gen_state_copy->degree, "Degrees are not aligned in generator");
    is(gen_state->field->n, gen_state_copy->field->n, "Field sizes do not agree");
    ok_memcmp(CCZP_PRIME(gen_state->field),
              CCZP_PRIME(gen_state_copy->field),
              sizeof(cc_unit) * gen_state->field->n,
              "Field Primes do not agree in generator deserialization");
    ok_memcmp(gen_state->coefficients,
              gen_state_copy->coefficients,
              (gen_state->degree + 1) * gen_state->field->n * sizeof(cc_unit),
              "mismatched polynomial coefficients");

    // Generate a threshold number of shares, with both generators, and ensure that they are the same. Store one set in the share
    // bag.
    for (uint32_t i = 1; i <= threshold; i++) {
        is(ccss_shamir_share_generator_generate_share(gen_state, i, share), CCERR_OK, "Failed to generate share");
        is(ccss_shamir_share_generator_generate_share(gen_state_copy, i, share2), CCERR_OK, "Failed to generate share");
        is(share->x, share2->x, "X coordinates do not match");
        ok_memcmp(share->y, share2->y, ccss_shamir_share_sizeof_y(share), "Mismatch in share y values for x = %d", share->x);
        is(ccss_shamir_share_bag_add_share(share_bag, share2), CCERR_OK, "Failed to add share to share bag");
    }
    // Recover the secret & verify that it matches the input secret.
    is(ccss_shamir_share_bag_recover_secret(share_bag, result_string, ccss_shamir_parameters_maximum_secret_length(params)),
       CCERR_OK,
       "failed in basic correctness test during recovery");
    ok_memcmp(sec,
              result_string,
              sizeof(sec),
              "Shamir Secret Creation and Recovery Failed in basic correctness "
              "test recovered secret does not match original:");

    // Clear up memory
    cc_clear(n, data);
    free(data);
    ccss_shamir_share_clear(share, params);
    ccss_shamir_share_clear(share2, params);
    ccss_shamir_share_bag_clear(share_bag, params);
    ccss_shamir_share_generator_clear(gen_state, params);
    ccss_shamir_share_generator_clear(gen_state_copy, params);
    ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
    free(result_string);
}

static void ccss_shamir_improper_deserialization_test()
{
    uint32_t threshold = 30;
/*    cc_unit p256_prime[] = { CCSS_PRIME_P256 };
    cc_size number_of_units_in_prime = CC_ARRAY_LEN(p256_prime);

    // create p256 prime for use as field for Shamir secrets
    cczp_decl_n(number_of_units_in_prime, prime);
    CCZP_N(prime) = number_of_units_in_prime;
    ccn_set(number_of_units_in_prime, CCZP_PRIME(prime), p256_prime);
    is(cczp_init(prime), CCERR_OK, "prime failed to initialize");
*/
    // Create random number generator for call to Shamir secret sharing
    int error = CCERR_OK;
    struct ccrng_state *rng_state = ccrng(&error);
    uint8_t sec[31] = { 0 };

    
    
    // Create parameters
    ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
    is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
       "Failed to intalize parameters");
    
    // Create a share to store generated shares temporary
    ccss_shamir_share_decl(share, params);
    ccss_shamir_share_init(share, params);
    
    
    uint8_t *result_string = malloc(ccss_shamir_parameters_maximum_secret_length(params));
    // Create a share generator with specified secret
    ccss_shamir_share_generator_decl(gen_state, params);
    is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec, sizeof(sec)),
       CCERR_OK,
       "Failed to initialize share generator");

    // Create a share bag, to store shares for reconstruction
    ccss_shamir_share_bag_decl(share_bag, params);
    ccss_shamir_share_bag_init(share_bag, params);

    // Serialize the generator
    size_t n;
    is(ccss_sizeof_shamir_share_generator_serialization(gen_state, &n), true, "Error with overflow in calculating ccss_sizeof_shamir_share_generator_serialization");
    uint8_t *data = malloc(n);
    is(ccss_shamir_share_generator_serialize(n, data, gen_state), CCERR_OK, "Error Serializing generator object");
    ccss_shamir_share_generator_decl(gen_copy_state, params);

    // Test improper data buffer length
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, 7, data),
       CCERR_PARAMETER,
       "Error Did not catch data buffer that is too short, not enough length for version and length of prime and length of threshold");

    // Test improper data buffer length
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n-1, data),
       CCERR_PARAMETER,
       "Error Did not catch data buffer that is too short in coefficients and prime");

    // Test improper data buffer length
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n+1, data),
       CCERR_PARAMETER,
       "Error Did not catch data buffer that is too short in coefficients and prime");
    
    // Test unsupported version in serialization
    data[0] = 2;
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_PARAMETER,
       "Error Did not catch bad version");
    data[0] = 1;
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_OK,
       "Reconstructed serialization should be ok");

    // Test length mismatch between serialization and params
    data[4] = (uint8_t)~data[4];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_PARAMETER,
       "Error Did not catch bad length");
    data[4] = (uint8_t)~data[4];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_OK,
       "Reconstructed serialization should be ok");

    // Test prime mismatch between serialization and params
    data[5] = (uint8_t)~data[5];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_PARAMETER,
       "Error Did not catch bad prime");
    data[5] = (uint8_t)~data[5];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_OK,
       "Reconstructed serialization should be ok");

    // Test Threshold mismatch between serialization and params
    data[37] = (uint8_t)~data[37];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_PARAMETER,
       "Error Did not catch bad threshold");
    data[37] = (uint8_t)~data[37];
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_OK,
       "Reconstructed serialization should be ok");

    // Test to catch coefficients that are larger than the prime.
    for (int i = 0; i < 32; i++) {
        data[41 + i] = 0xFF;
    }
    is(ccss_shamir_share_generator_deserialize(gen_copy_state, params, n, data),
       CCERR_PARAMETER,
       "Error Did not catch bad prime");

    // Clear up memory
    cc_clear(n, data);
    free(data);
    ccss_shamir_share_clear(share, params);
    ccss_shamir_share_bag_clear(share_bag, params);
    ccss_shamir_share_generator_clear(gen_state, params);
    ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
    free(result_string);
}


static void ccss_shamir_de_serialization_overflow_test()
{
    uint32_t threshold = 30;
    
    // Create random number generator for call to Shamir secret sharing
    int error = CCERR_OK;
    struct ccrng_state *rng_state = ccrng(&error);
    uint8_t sec[31] = { 0 };

    // Create parameters
    ccss_shamir_parameters_decl(params, sizeof(CCSS_PRIME_P256));
    is(ccss_shamir_parameters_init(params, sizeof(CCSS_PRIME_P256), CCSS_PRIME_P256, threshold), CCERR_OK,
       "Failed to initialize parameters");

    // Create a share to store generated shares temporary
    ccss_shamir_share_decl(share, params);
    ccss_shamir_share_init(share, params);


    uint8_t *result_string = malloc(ccss_shamir_parameters_maximum_secret_length(params));
    // Create a share generator with specified secret
    ccss_shamir_share_generator_decl(gen_state, params);
    is(ccss_shamir_share_generator_init(gen_state, params, rng_state, sec, sizeof(sec)),
       CCERR_OK,
       "Failed to initialize share generator");

    // Test sizeof_generator calculations  the generator.
    // Illegally change the degree of the polynomial to trigger overflow on 32-bit devices
    gen_state->degree = 0xFFFFFFFF;

    bool expected_sizeof_result = sizeof(size_t) == 4 ? false: true;  // Test will only overflow on 32-bit devices

    size_t n;
    is(ccss_sizeof_shamir_share_generator_serialization(gen_state, &n), expected_sizeof_result, "Error with overflow in calculating ccss_sizeof_shamir_share_generator_serialization");

    gen_state->degree = 0xFFFFFFFA;
    is(ccss_sizeof_shamir_share_generator_serialization(gen_state, &n), expected_sizeof_result, "Error with overflow in calculating ccss_sizeof_shamir_share_generator_serialization");

    gen_state->degree = 29;

    ccss_shamir_share_clear(share, params);
    ccss_shamir_share_generator_clear(gen_state, params);
    ccss_shamir_parameters_clear(params, sizeof(CCSS_PRIME_P256));
    free(result_string);
}

int ccss_shamir_tests(void)
{
    ccss_shamir_basic_correctness_test();
    ccss_shamir_basic_ccss_shamir_share_generator_init_with_secrets_less_than_prime_correctness_test();
    ccss_shamir_basic_internal_tests();
    ccss_shamir_basic_internal_test_with_leading_zeros();
    ccss_shamir_shares_out_of_bounds_test();
    ccss_shamir_shares_secret_too_big_test();
    ccss_shamir_threshold_too_small_test();
    ccss_shamir_bag_not_full_test();
    ccss_shamir_conflicting_share_test();
    ccss_shamir_threshold_bigger_than_field_test();
    ccss_shamir_basic_import_export_test();
    ccss_shamir_string_into_field_test();
    ccss_shamir_basic_serialization_test();
    ccss_shamir_improper_deserialization_test();
    ccss_shamir_de_serialization_overflow_test();
    return CCERR_OK;
}
