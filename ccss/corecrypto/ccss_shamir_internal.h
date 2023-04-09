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

#ifndef CORECRYPTO_CCSS_SHAMIR_INTERNAL_H
#define CORECRYPTO_CCSS_SHAMIR_INTERNAL_H

#include <corecrypto/ccss_shamir.h>
#include "cczp_internal.h"

#define CCSS_SHAMIR_GEN_STATE_FIELD(poly) ((poly)->field)
#define CCSS_SHAMIR_SHARE_FIELD(point) ((point)->field)
#define CCSS_SHAMIR_SHARE_BAG_FIELD(share_bag) ((share_bag)->field)
#define CCSS_SHARE_MINIMUM_THRESHOLD 2

/// @function ccss_shamir_generate_random_poly_ws
/// @brief Generate a random polynomial.
/// @param ws Workspace.
/// @param poly An initialized polynomial data structure (aka. share generator).
/// @param rng_state The random number generator to be used to generate the random polynomial.
/// @discussion The function takes in the pointer a polynomial with its field and  degree initialized  sets all the coefficients to random elements in the field, with the exception of the highest degree coeffieicnt which cannot be 0.
/// @return CCERR_OK if successful, error otherwise
///
CC_NONNULL_ALL
int ccss_shamir_generate_random_poly_ws(cc_ws_t ws, ccss_shamir_share_generator_state_t poly, struct ccrng_state *rng_state);

/// @function ccss_shamir_poly_coefficient
/// @brief Returns a pointer to the ith coefficient of the polynomial poly (index i returns coefficient of x^i, i may be 0)
/// @param poly a pointer to the ccss_shamir_poly structure that represents the initialized poly
/// @param i index of the coefficient, with i being the coefficient of x^i.
/// @return returns a const cc_unit* to the beginning of the i'th coefficient of poly. If i larger than the degree it returns null.
///
CC_NONNULL_ALL
cc_unit* ccss_shamir_poly_coefficient(const ccss_shamir_share_generator_state_t poly, uint32_t i);

/// @function ccss_shamir_evaluate_poly_to_buffer
/// @brief Computes y=poly(x) and sets point=(x,y)
/// @param poly The polynomial which will be evaluated to
/// @param x The value x to compute the polynomial on.
/// @param y The value of y=poly(x).
/// @return CCERR_OK if successful
///
CC_NONNULL_ALL
int ccss_shamir_evaluate_poly_to_buffer(const ccss_shamir_share_generator_state_t poly, uint32_t x, cc_unit *y);

/// @function ccss_shamir_generate_share_poly_ws
///
/// @brief Generates a polynomial used to create Shamir secret shares.
/// @discussion Called to create a polynomial with constant coefficient corresponding to the supplied secret.
///
/// @param ws Workspace.
/// @param poly An intialized share generator.
/// @param secret_nbytes The number of uint8_t needed to represent the parameter secret
/// @param secret A pointer to the secret to be used for the secret share
/// @param exact_secrets true if secret can be any value less than prime p, and false if secret must be at least 1 byte smaller than prime p
/// @return CCERR_OK if successful
/// @discussion Runtime is independent of the secret's value, but not its byte length. If concerned about leaking the secret's length, pass in a secret that is padded to length of poly's field element.
///
CC_NONNULL_ALL
int ccss_shamir_generate_share_poly_ws(cc_ws_t ws, ccss_shamir_share_generator_state_t poly, struct ccrng_state *rng_state, size_t secret_nbytes, const uint8_t *secret, bool exact_secrets);

/// @function ccss_shamir_poly_n
/// @brief Given an initialized share generator, it returns the number of cc_units used to represent an element in the field that the shares are generated over.
/// @param poly a pointer to an initialized share generator.
/// @return The number of cc_units needed to represent elements in the prime field the polynomial is defined over
///
CC_NONNULL_ALL
cc_size ccss_shamir_poly_n(const ccss_shamir_share_generator_state_t poly);

/// @function ccss_shamir_prime_of
/// @brief Access function to the field the share_ generator is defined over.
/// @param poly An initialized share generator
/// @return A pointer to the field over which the polynomial is defined over.
///
CC_NONNULL_ALL
cczp_const_t ccss_shamir_prime_of(const ccss_shamir_share_generator_state_t poly);

/// @function ccss_shamir_init_share_poly
/// @brief Initializes a polynomial with given degree over the specified field using the provided coefficient_buffer for storage.
/// @param poly A pointer to the ccss_shamir_poly polynomial that will be created.
/// @param params An initialized params structure specifying the field and threshold.
///
CC_NONNULL_ALL
void ccss_shamir_init_share_poly(ccss_shamir_share_generator_state_t poly, const ccss_shamir_parameters_t params);

/// @function ccss_shamir_share_bag_copy_ith_share_x
/// @brief Returns the x value of the ith share in the share bag.
/// @param share_bag initialized share bag
/// @param index index of the share (starting at 0) to retrieve
/// @return The x value of the ith share
/// @discussion  Function will abort if index does not correspond to a share
///
CC_NONNULL_ALL
uint32_t ccss_shamir_share_bag_copy_ith_share_x(ccss_shamir_share_bag_t share_bag, uint32_t index);

/// @function ccss_shamir_share_bag_ith_share_y
/// @brief Returns  a pointer to the y value of the ith share in the share bag.
/// @param share_bag initialized share bag
/// @param index index of the share (starting at 0) to retrieve
/// @return A pointer to the y value of the ith share
/// @discussion Function will abort if index does not correspond to a share.
///
CC_NONNULL_ALL
cc_unit *ccss_shamir_share_bag_ith_share_y(ccss_shamir_share_bag_t share_bag, uint32_t index);

/// @function ccss_shamir_share_bag_set_ith_share_with_xy
/// @brief Sets the ith share in the share bag to value (x,y)
/// @param share_bag initialized share bag
/// @param index index of the share (starting at 0) to retrieve
/// @param x the x coordinate of the share
/// @param y the y coordinate of the share
/// @return CCERR_OK if successful, and error otherwise
///
CC_NONNULL_ALL
int ccss_shamir_share_bag_set_ith_share_with_xy(ccss_shamir_share_bag_t share_bag, uint32_t index, uint32_t x, const cc_unit *y);

/// @function ccss_shamir_share_bag_set_ith_share
/// @brief Copies the share provided into the Index/ith location of the share bag.
/// @param share_bag An initialized share bag
/// @param index the position in the bag where the share should be set
/// @param share The share to copy into the bag at position index. Should have the same field as the share bag.
/// @return CCERR_OK if successful, and error otherwise
///
CC_NONNULL_ALL
int ccss_shamir_share_bag_set_ith_share(ccss_shamir_share_bag_t share_bag, uint32_t index, const ccss_shamir_share_t share);

///@function ccss_shamir_consistent_primes
/// @brief Returns CERR_OK if the fields are equivalent (by value), and an error otherwise.
/// @param field_r First field to compare
/// @param field_l Second field to compare.
/// @return CCERR_OK if shares are consistent, and error otherwise
///
CC_NONNULL_ALL
int ccss_shamir_consistent_primes(cczp_const_t field_l, cczp_const_t field_r);

/// @function ccss_encode_string_into_value_smaller_than_prime
/// @brief Function to encode a  string (interpreted as a big endian number)  into a field element.
/// @param field The field that we are encoding  into.
/// @param dest The destination field element
/// @param string The bytes defining the string to be encoded
/// @param string_nbytes the byte length of the string
/// @return CCERR_OK if string encoded, or error otherwise
/// @discussion This function treats string as a big endian number, converts it to little endian, and ensures the value is smaller than the prime defining the field.
/// Runtime is independent of secrets value, but not its byte length.
///
CC_NONNULL_ALL
int ccss_encode_string_into_value_smaller_than_prime(cczp_const_t field, cc_unit *dest, size_t string_nbytes, const uint8_t *string);

/// @function ccss_shamir_secret_one_byte_smaller_than_prime
/// @brief Function to ensure that a secret fits in the field. It ensures that the prime requires at least one more byte of storage than than the secret (which is byte aligned), to ensure that callers don't try and match bit lengths exactly, and end up with issues where secret > prime, but |secret| = |prime|.
/// @param field Field that the secret will be embedded into
/// @param secret_nbytes Number of bytes that the secret takes.
/// @return true if the number of bytes in secret is less than the number of bytes needed to represent the prime defining the field , and false otherwise
///
CC_NONNULL_ALL
bool ccss_shamir_secret_one_byte_smaller_than_prime(cczp_const_t field,  size_t secret_nbytes);

#endif /* CORECRYPTO_CCSS_SHAMIR_INTERNAL_H */
