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

#ifndef CORECRYPTO_CCSS_SHAMIR_H
#define CORECRYPTO_CCSS_SHAMIR_H

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn.h>
#include <limits.h>
#include <stdbool.h>

// Define some primes that might be useful for common Shamir secret sharing cases, namely all of the NIST elliptic
// curve primes.
// NOTE: Secret sharing provides information theoretic security. Your security level is not tied to the size of the prime used to generate shares.
//       Rather, you should select your prime so that it holds the secrets you intend to produce.

extern const uint8_t CCSS_PRIME_P192[24];
extern const uint8_t CCSS_PRIME_P224[28];
extern const uint8_t CCSS_PRIME_P256[32];
extern const uint8_t CCSS_PRIME_P384[48];
extern const uint8_t CCSS_PRIME_P521[66];

// Polynomial data structure for polynomials over Z_p.
// If p(x)= \Sum_i=0^m c_i*x^i over Z_p
// Then cczp is initialized for Z_p
// degree<-m
// Assuming it takes n units to represent an integer mod p
// c_0 = coefficients[0]...coefficients[n-1]
// c_1 = coefficients[n]...coefficients[2n-1]
// ..
// c_m = coefficients[n(m-1)]...coefficients [nm-1]
typedef struct ccss_shamir_share_generator {
    cczp_const_t field;
    uint32_t degree;
    cc_unit coefficients[];
} *ccss_shamir_share_generator_state_t, ccss_shamir_share_generator_state;

// Shares are represented as points (x,y), where y=p(x) for a ccss_shamir_poly, which is defined over a finite modular number field
// defined by the prime (Z_p)
// uint32_t x the x coordinate of the point. Given that we do not anticipate needing more than 2^32 shares we limit to one uint32_t.
// cc_unit *y coordinate of point.
typedef struct ccss_shamir_share {
    cczp_const_t field;
    uint32_t x;  // Use a small x, since we'll always have a small number of shares.
    cc_unit y[]; // y should be defined to be of length n, for n defined by prime in field.
} *ccss_shamir_share_t, ccss_shamir_share;

// A structure that holds the parameters for the generation of a share, share_generator for share creation, or share_bag for secret recovery.
typedef struct ccss_shamir_parameters {
    uint32_t threshold;
    struct cczp field;
} *ccss_shamir_parameters_t, ccss_shamir_parameters;

// A structure that accumulates shares for use in secret recovery, and where generated shares are placed.
// Shares are stored as an array of (x,y) points where x is a uint32_t and y is an array of cc_units of length field->n.
// Since we don't want a bunch of complicated compile time macros we stuff the uint32_t into a cc_unit.
// So the shares array should look like the following
// |x_1| y_1....|x_2| y_2....| ....
typedef struct ccss_shamir_share_bag {
    ccss_shamir_parameters_t params;
    uint32_t share_count;
    cc_unit shares[];
} *ccss_shamir_share_bag_t, ccss_shamir_share_bag;

// Size of share bag
size_t ccss_sizeof_share_bag(const ccss_shamir_parameters_t params);

// Macros used to create and clear share bags.
#define ccss_shamir_share_bag_decl(_name_, _params_) cc_ctx_decl(struct ccss_shamir_share_bag, ccss_sizeof_share_bag(_params_), _name_)
#define ccss_shamir_share_bag_clear(_name_, _params_) cc_clear(ccss_sizeof_share_bag(_params_), _name_)

// Size of a share
size_t ccss_sizeof_share(const ccss_shamir_parameters_t params);

// Macros used to create and clear shares
#define ccss_shamir_share_decl(_name_, _params_) cc_ctx_decl(struct ccss_shamir_share, ccss_sizeof_share(_params_), _name_)
#define ccss_shamir_share_clear(_name_, _params_) cc_clear(ccss_sizeof_share(_params_), _name_)

// Size of a share generator
size_t ccss_sizeof_generator(const ccss_shamir_parameters_t params);

// Macros used to create and clear share generators
#define ccss_shamir_share_generator_decl(_name_, _params_) cc_ctx_decl(struct ccss_shamir_share_generator, ccss_sizeof_generator(_params_), _name_)
#define ccss_shamir_share_generator_clear(_name_, _params_) cc_clear(ccss_sizeof_generator(_params_),  _name_)

// Size of parameters
size_t ccss_sizeof_parameters(size_t prime_nbytes);

// Macro used to create and clear parameters
#define ccss_shamir_parameters_decl(_name_, _size_) cc_ctx_decl(struct ccss_shamir_parameters, ccss_sizeof_parameters(_size_), _name_)
#define ccss_shamir_parameters_clear(_name_, _size_) cc_clear(ccss_sizeof_parameters(_size_), _name_)

/// @function ccss_shamir_parameters_init
/// @brief Constructs a param structure used to initiate shares, generators and share bags that are meant to be used together.
/// @param params A pointer to the data structure that will contain the field and threshold
/// @param prime_nbytes Length of the prime number in bytes that defines the field for shares.
/// @param prime A prime number that defines the fields the shares will be (re)-constructed over.
/// @param threshold The minimum number of shares that will be needed for reconstruction of the secret.
/// @return CCERR_OK if successful, and error code otherwise.
/// @discussion Use the macro ccss_shamir_parameters_decl to create a shamir_parameters data structure, and ccss_shamir_parameters_clear to clear the memory when done.
///
CC_NONNULL_ALL
int ccss_shamir_parameters_init(ccss_shamir_parameters_t params, size_t prime_nbytes, const uint8_t *prime, uint32_t threshold);

/// @function ccss_shamir_parameters_maximum_secret_length
/// @param params An intialized parameter used for a generator or share bag.
/// @return the maximum size of a secret that can be embedded in a generator with these paramaters, or returned from a share bag with these parameters.
CC_NONNULL_ALL
size_t ccss_shamir_parameters_maximum_secret_length(const ccss_shamir_parameters_t params);

/// @function ccss_shamir_share_generator_init
/// @brief Initializes a secret share generator with the specified secret. Secret must be 1 byte smaller than the number of bytes needed to represent the prime defining the field
/// @param state a pointer to the ccss_shamir_share_generator_state that will be initialized.
/// @param params An initialized params structure that specifies the field and threshold with which one would like to initiate the generator.
/// @param rng_state a random number generator that will be used for randomness in share creation.
/// @param secret a pointer to the secret that will be shared, must be 1 byte shorter than prime field specified in params.
/// @param secret_nbytes the size of the secret that will be shared (in bytes).
/// @return CCERR_OK if successful, and error code otherwise.
/// @discussion Creates an initialized generator state that can be used to generate shares.
/// Important. Note: Runtime is independent of the secret's value, but not its byte length. If one is concerned about leaking secret then pass in a secret that is padded to the byte length of the parameter's field.
///
CC_NONNULL_ALL
int ccss_shamir_share_generator_init(ccss_shamir_share_generator_state_t state, const ccss_shamir_parameters_t params, struct ccrng_state *rng_state, const uint8_t *secret, size_t secret_nbytes);


/// @function ccss_shamir_share_generator_init_with_secrets_less_than_prime
/// @brief Initializes a secret share generator with the specified secret.
/// @param state a pointer to the ccss_shamir_share_generator_state that will be initialized.
/// @param params An initialized params structure that specifies the field and threshold with which one would like to initiate the generator.
/// @param rng_state a random number generator that will be used for randomness in share creation.
/// @param secret a pointer to the secret that will be shared, must be  a value smaller than the prime p defining field
/// @param secret_nbytes the size of the secret that will be shared (in bytes).
/// @return CCERR_OK if successful, and error code otherwise.
/// @discussion Creates an initialized generator state that can be used to generate shares. *Should only be used if algebraic accuracy in share secret is necessary.*  Important. Note: Runtime is independent of the secret's value, but not its byte length. If one is concerned about leaking secret then pass in a secret that is padded to the byte length of the parameter's field.
///
int ccss_shamir_share_generator_init_with_secrets_less_than_prime(ccss_shamir_share_generator_state_t state,
                                     const ccss_shamir_parameters_t params,
                                     struct ccrng_state *rng_state,
                                     const uint8_t *secret,
                                     size_t secret_nbytes);


/// Provides the length of the buffer in bytes that is needed to serialize the given share generator.
/// @param state Share generator that is to be serialized
/// @param size The size of the serialization
/// @return true if size fits in size_t, and false if it results in an overflow. If false, size is not updated.
bool ccss_sizeof_shamir_share_generator_serialization(const ccss_shamir_share_generator_state_t state, size_t *size);

/// Serializes a share generator (Shamir polynomial), so that it can later be reconstituted with the same randomness, and therefore create consistent/interchangeable or duplicate shares with the given generator.
/// @param data_n The length of the serialization buffer to write serialization to. Should be the length provided by ccss_sizeof_shamir_share_generator_serialization
/// @param data Serialization buffer 
/// @param state The share generator that will be serialized
int ccss_shamir_share_generator_serialize(size_t data_n, uint8_t *data, const ccss_shamir_share_generator_state_t state);

/// Instantiates a share generator with the given params and the provided serialization.
/// @param state The share generator to instantiate
/// @param params The field and threshold that the share generator will be instantiated with.
/// @param data_nbytes length of the generator serialization
/// @param data serialization data
/// @discussion The function will verify that the serialization was for the same prime and threshold that are given in params.
int ccss_shamir_share_generator_deserialize(ccss_shamir_share_generator_state_t state, const ccss_shamir_parameters_t params, size_t data_nbytes, const uint8_t *data);

/// @function ccss_shamir_share_generator_generate_share
/// @brief generates the share with x=index, and copies it into share.
/// @param state An initialized share generator
/// @param index The index of the share you want. Shares can be generated on indices 1 through MIN(2^32-1, P-1) where P is the prime in params that the generator is instantiated with.
/// @param share An initialized share which will have the index-th share copied into it.
/// @return CCERR_OK if successful, and error code otherwise.
///
CC_NONNULL_ALL
int ccss_shamir_share_generator_generate_share(const ccss_shamir_share_generator_state_t state, uint32_t index, ccss_shamir_share_t share);

/// @function ccss_shamir_share_bag_init
/// @brief Initialize a share bag, so that it is ready to be used to receive shares to recover a shared secret.
/// @param share_bag  The share bag to be initialized.
/// @param params An initialized params structure that specifies the field and threshold you would like to initiate the bag with. The bag holds threshold shares, as after that many the secret can be reconstructed.
///
CC_NONNULL_ALL
void ccss_shamir_share_bag_init(ccss_shamir_share_bag_t share_bag, const ccss_shamir_parameters_t params);
 
/// @function ccss_shamir_share_bag_add_share
/// @brief Adds a share to the given share_bag if there is room. Checking is done to ensure that there is already not a share with the same x value in the bag, an error is returned on collision.
/// @param share_bag  An initialized share bag which the share will be added to.
/// @param share The share to be copied into the share bag
/// @return CCERR_OK if successful, and error code otherwise.
///
CC_NONNULL_ALL
int ccss_shamir_share_bag_add_share(ccss_shamir_share_bag_t share_bag, const ccss_shamir_share_t share);

/// @function csss_shamir_share_bag_can_recover_secret
/// @brief Tells you whether a threshold number of secrets have been put into the bag, and thus if the secret can be reconstructed.
/// @param share_bag an initialized share_bag, with or without shares in it.
/// @return true if the bag has threshold shares, and false otherwise
///
CC_NONNULL_ALL
bool csss_shamir_share_bag_can_recover_secret(const ccss_shamir_share_bag_t share_bag);

/// @function ccss_shamir_share_bag_recover_secret
/// @brief Reconstructs a secret from shares in the share_bag, and stores them in result. Result should have allocated memory sufficient to hold the secret.
/// This should be at most the prime size associated with the share bag.
/// @param share_bag An initialized share bag
/// @param result a pointer to an array that will be overwritten that can hold an element of field associated with the share bag.
/// @param result_nbytes the length of the buffer where result can be copied.
/// @return CCERR_OK on  retrieval of the secret (where result is overwritten with the secret), and an error code otherwise.
/// @discussion If the secret is larger than result_nbytes, the secret will be truncated to its result_nbytes most significant bytes.
/// NOTE: Retrieval will return a value corresponding to the shares in the sharebag, if there are sufficient shares. However, if these shares do not correspond
/// to shares that were properly generated with a call to ccss_shamir_generate_copy_out_index_share for a fixed share generator, then the recovered secret is not
/// likely to correspond to the secret originally shared for any of the shares. This will not be reported as an error, as there is no way for the algorithm to discern between such cases.
CC_NONNULL_ALL
int ccss_shamir_share_bag_recover_secret(const ccss_shamir_share_bag_t share_bag, uint8_t *result, size_t result_nbytes);

/// @function ccss_shamir_share_init
/// @brief Initialize a share to work with inputs in the field specified by params
/// @param share a ccss_shamir_share to be initialized. 
/// @param params An initialized params structure that specifies the field and threshold you would like to initiate the generator with.
/// @discussion Use ccss_shamir_share_decl, and ccss_shamir_share_clear macros to define and clear share structures.
///
CC_NONNULL_ALL
void ccss_shamir_share_init(ccss_shamir_share_t share, const ccss_shamir_parameters_t params);

/// @function ccss_shamir_share_import
/// @param share An initialized share that will be populated with a copy of x and y
/// @param x the value to set the x value of the share
/// @param y A pointer to the value of y that will be copied into the share
/// @param y_nbytes the number of bytes in y.
/// @return CCERR_OK or error.
///
CC_NONNULL_ALL
int ccss_shamir_share_import(ccss_shamir_share_t share, uint32_t x, const uint8_t *y, size_t y_nbytes);


/// @function ccss_shamir_share_sizeof_y
/// @param share An initialized  share
/// @return the size of a buffer needed to hold the exported y value of the share
size_t ccss_shamir_share_sizeof_y(const ccss_shamir_share_t share);

/// @function ccss_shamir_share_export
/// @param share The share from which x and y will be retrieved
/// @param x A pointer to where to place the x value of the share
/// @param y A pointer to where to copy the y value of the share
/// @param y_nbytes The length of the y buffer that has been allocated.
/// @return CCERR_OK or error.
///
CC_NONNULL_ALL
int ccss_shamir_share_export(const ccss_shamir_share_t share, uint32_t *x, uint8_t *y, size_t y_nbytes);

#endif /* CORECRYPTO_CCSS_SHAMIR_H */
