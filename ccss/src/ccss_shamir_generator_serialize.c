/* Copyright (c) (2020,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include <corecrypto/cc_priv.h>

bool ccss_sizeof_shamir_share_generator_serialization(const ccss_shamir_share_generator_state_t state, size_t *size)
{
    // 1 byte for version, 4 each for n and for threshold, n*sizeof(cc_unit) for prime, and n*sizeof(cc_unit)*(degree+1) for
    // coefficients
    size_t tally_size;
    cc_require(!cc_add_overflow(state->degree, 2, &tally_size), errOut);
    cc_require(!cc_mul_overflow(tally_size, ccn_sizeof_n(cczp_n(CCSS_SHAMIR_GEN_STATE_FIELD(state))), &tally_size), errOut);
    cc_require(!cc_add_overflow(tally_size, 9, &tally_size), errOut);
    *size = tally_size;
    
    return true;
errOut:
    return false;
}

// Serialization format is as follows:
// version || n = length of prime/coefficients in bytes || prime || threshold || c_0 || c_1 ||... || c_threshold (coefficient
// array)
// version is 1 byte, and currently must be set to 1.
// n  output as 4 bytes in big endian format
// prime is n bytes in big endian format
// threshold is 4 bytes in big endian format
// c_i is n bytes for each i, each in big endian format
// Coefficient array represets poly  \sum_{i=0}^threshold, c_i*x^i

int ccss_shamir_share_generator_serialize(size_t data_n, uint8_t *data, const ccss_shamir_share_generator_state_t state)
{
    CC_ENSURE_DIT_ENABLED

    size_t index = 0;
    size_t serialization_size_nbytes;

    // Perform check to ensure that data_n has enough holding capacity
    cc_require_or_return(ccss_sizeof_shamir_share_generator_serialization(state, &serialization_size_nbytes), CCERR_PARAMETER);
    cc_require_or_return(data_n >= serialization_size_nbytes, CCERR_PARAMETER);
    
    // Output data necessary to serialize a share generator in a fashion that is easy to parse and validate.
    
    // output version = 1
    data[index] = 1;
    index++;
    
    // Output n in 4 bytes for field length
    cc_size n = CCZP_N(CCSS_SHAMIR_GEN_STATE_FIELD(state));
    size_t big_num_byte_n = ccn_sizeof_n(n);
    cc_require_or_return(big_num_byte_n <= UINT32_MAX, CCERR_OVERFLOW);
    uint32_t big_num_byte_n32 = (uint32_t)big_num_byte_n;
    cc_store32_be(big_num_byte_n32, &data[index]);
    index += sizeof(uint32_t);
    
    // output polynomial degree/threshold
    uint32_t threshold = state->degree;
    cc_store32_be(threshold, &data[index]);
    index += sizeof(uint32_t);

    // Output prime
    int error = CCERR_OK;
    cc_require(
        (error = ccn_write_uint_padded_ct(n, CCZP_PRIME(CCSS_SHAMIR_GEN_STATE_FIELD(state)), big_num_byte_n, &data[index])) >= 0,
        errOut);
    index += big_num_byte_n;
    
    // output coefficients * threshold
    for (uint32_t i = 0; i <= threshold; i++) {
        cc_require((error = ccn_write_uint_padded_ct(n, &state->coefficients[i * n], big_num_byte_n, &data[index])) >= 0, errOut);
        index += big_num_byte_n;
    }
    error = CCERR_OK; //Ensure that if error > 0 due to padding in ccn_write... that it is set back to CCERR_OK.
errOut:
    return error;
}

int ccss_shamir_share_generator_deserialize(ccss_shamir_share_generator_state_t state,
                                            const ccss_shamir_parameters_t params,
                                            size_t data_nbytes,
                                            const uint8_t *data)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = params->field.n;
    CC_DECL_WORKSPACE_OR_FAIL(ws, n);
    CC_DECL_BP_WS(ws, bp);

    int error = CCERR_OK;
    ccss_shamir_init_share_poly(state, params);
    size_t index = 0;
    
    // Ensure data buffer has version and prime length encoding.
    cc_require_action(data_nbytes > 9, errOut, error = CCERR_PARAMETER);
    
    // Verify version
    cc_require_action(data[index] == 1, errOut, error = CCERR_PARAMETER);
    index += 1;

    // Verify prime length
    uint32_t big_num_byte_n = cc_load32_be(&data[index]);
    index += sizeof(uint32_t);
    cc_require_action(big_num_byte_n >= 1, errOut, error = CCERR_PARAMETER);
    cc_require_action((n == ccn_nof_size(big_num_byte_n)), errOut, error = CCERR_PARAMETER);
 
    // Retrieve Threshold/poly degree
    state->degree = cc_load32_be(&data[index]);
    cc_require_action(state->degree < UINT32_MAX, errOut, error = CCERR_PARAMETER);
    cc_require_action(state->degree + 1 == params->threshold, errOut, error = CCERR_PARAMETER);
    index += sizeof(uint32_t);
    
    // Verify that data buffer is big enough to contain all the coefficients, the prime, size and version parameters.
    size_t tally_size;
    cc_require_action(!cc_add_overflow(1, (size_t)params->threshold, &tally_size), errOut, error = CCERR_PARAMETER);
    cc_require_action(!cc_mul_overflow(tally_size, (size_t) big_num_byte_n, &tally_size), errOut, error = CCERR_PARAMETER);
    cc_require_action(!cc_add_overflow(tally_size, (size_t) 9, &tally_size), errOut, error = CCERR_PARAMETER);
    cc_require_action (data_nbytes == tally_size, errOut, error = CCERR_PARAMETER);
    
    // Verify Prime
    cc_unit *prime = CC_ALLOC_WS(ws, n);
    cc_require((error = ccn_read_uint(n, prime, big_num_byte_n, &data[index])) == CCERR_OK, errOut);
    cc_require_action(0 == ccn_cmp(n, prime, cczp_prime(CCSS_SHAMIR_GEN_STATE_FIELD(state))), errOut, error = CCERR_PARAMETER);
    index += big_num_byte_n;

    // output coefficients * threshold
    for (uint32_t i = 0; i <= state->degree; i++) {
        cc_require_action((error = ccn_read_uint(n, &state->coefficients[i * n], big_num_byte_n, &data[index])) == CCERR_OK,
                          errOut,
                          error = CCERR_PARAMETER);
        cc_require_action(ccn_cmp(n, &state->coefficients[i * n], cczp_prime(CCSS_SHAMIR_GEN_STATE_FIELD(state))) == -1,
                          errOut,
                          error = CCERR_PARAMETER);
        index += big_num_byte_n;
    }
errOut:
    CC_FREE_BP_WS(ws, bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return error;
}
