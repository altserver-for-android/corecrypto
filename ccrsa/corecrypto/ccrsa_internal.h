/* Copyright (c) (2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRSA_INTERNAL_H_
#define _CORECRYPTO_CCRSA_INTERNAL_H_

#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_fault_canary.h>
#include "cczp_internal.h"

CC_NONNULL((1))
bool ccrsa_pairwise_consistency_check(const ccrsa_full_ctx_t full_key,
                                      struct ccrng_state *rng);

#define CCRSA_SIG_LEN_VALIDATION_STRICT 0
#define CCRSA_SIG_LEN_VALIDATION_ALLOW_SHORT_SIGS 0x7dcdc05e

/*!
@function   ccrsa_generate_key_internal
@abstract   Generate a nbit RSA key pair.

@param      nbits    Bit size requested for the key
@param      fk       Allocated context where the generated key will be stored
@param      e_nbytes Byte size of the input public exponent
@param      e        Input public exponent in big endian. Recommend value is {0x01, 0x00, 0x01}
@param      rng      Random Number generator for prime generation.
@param      rng_mr   Random Number generator for primality testing.
@result     CCERR_OK if no error

@discussion
    fk should be allocated using ccrsa_full_ctx_decl_nbits(nbits, fk).
    The unsigned big endian byte array exponent e of length e_size is used as the exponent. It's an error to call this function with an exponent larger than nbits
*/
CC_NONNULL_ALL
int ccrsa_generate_key_internal(size_t nbits, ccrsa_full_ctx_t fk,
                                size_t e_nbytes, const uint8_t *e,
                                struct ccrng_state *rng,
                                struct ccrng_state *rng_mr);

/*!
@function   ccrsa_verify_pkcs1v15_internal
@abstract   Perform RSA PKCS1v15 verification.

@param      key                        Full key
@param      oid                        OPTIONAL OID describing the type of digest passed in
@param      digest_len                 Byte length of the digest
@param      digest                     Digest buffer
@param      sig_len                    Byte length of signature
@param      sig                        Signature buffer
@param      sig_len_validation         Flag designating whether strict validation OR short signatures are allowed.
@param      fault_canary_out           OPTIONAL cc_fault_canary_t (See discussion)

@result     CCERR_VALID_SIGNATURE on valid signature
           CCERR_INVALID_SIGNATURE on invalid signature
           other indicating some failure

 @discussion If the fault_canary_out argument is not NULL, CCRSA_PKCS1_FAULT_CANARY will be written to
 fault_canary_out if the signature is valid. This is useful in contexts where fault attacks are within the
 threat model: a computational fault that forces the return value to be 0 on an invalid signature should
 not cause the fault_canary_out buffer to be equal to CCRSA_PKCS1_FAULT_CANARY. Callers can use CC_FAULT_CANARY_EQUAL
 to check fault_canary_out against CCRSA_PKCS1_FAULT_CANARY.
*/
CC_NONNULL((1, 4, 6))
int ccrsa_verify_pkcs1v15_internal(ccrsa_pub_ctx_t key, const uint8_t *oid,
                                   size_t digest_len, const uint8_t *digest,
                                   size_t sig_len, const uint8_t *sig,
                                   int sig_len_validation, cc_fault_canary_t fault_canary_out);

CC_NONNULL((1, 2, 5, 7))
int ccrsa_verify_pkcs1v15_internal_ws(cc_ws_t ws, ccrsa_pub_ctx_t key,
                                      const uint8_t *oid,
                                      size_t digest_len, const uint8_t *digest,
                                      size_t sig_len, const uint8_t *sig,
                                      int sig_len_validation, cc_fault_canary_t fault_canary_out);

/*!
@function   ccrsa_emsa_pkcs1v15_verify_canary_out
@abstract   Perform PKCS1v15 verification.

@param      emlen               Byte length of the input encoded message
@param      em                  Input encoded message
@param      dgstlen             Byte length of the digest
@param      dgst                Digest buffer
@param      oid                 OPTIONAL OID describing the type of digest passed in
@param      fault_canary_out   OPTIONAL cc_fault_canary_t (See discussion)

@result     0 on verification success, non-zero otherwise.

@discussion If the fault_canary_out argument is not NULL, CCRSA_PKCS1_FAULT_CANARY will be written to
fault_canary_out if the signature is valid. This is useful in contexts where fault attacks are within the
threat model: a computational fault that forces the return value to be 0 on an invalid signature should
not cause the fault_canary_out buffer to be equal to CCRSA_PKCS1_FAULT_CANARY. Callers can use CC_FAULT_CANARY_EQUAL
to check fault_canary_out against CCRSA_PKCS1_FAULT_CANARY.
*/
CC_NONNULL((2, 4))
int ccrsa_emsa_pkcs1v15_verify_canary_out(size_t emlen, uint8_t *em,
                                          size_t dgstlen, const uint8_t *dgst,
                                          const uint8_t *oid,
                                          cc_fault_canary_t fault_canary_out);

/*!
@function ccrsa_emsa_pss_decode_canary_out_ws
@abstract Perform PSS verification.

@param   ws                Workspace
@param   di                The hash algorithm applied to the message
@param   MgfDi             The hash algorithm for thr mask generation function
@param   sSize             The salt size in bytes
@param   mSize             The length of the input hash. Must be equal to di->output_size
@param   mHash             The hash of the input message.
@param   emBits            The length of the encoded message in bits
@param   EM                The encoded message, an octet string of length emLen = ⎡emBits/8⎤
@param   fault_canary_out  cc_fault_canary_t (See discussion)
 
@result     0 on verification success, non-zero otherwise.
 
@discussion CCRSA_PSS_FAULT_CANARY will be written to fault_canary_out if the
 signature is valid. This is useful in contexts where fault attacks are within the
 threat model: a computational fault that forces the return value to be 0 on an invalid signature should
 not cause the fault_canary_out buffer to be equal to CCRSA_PSS_FAULT_CANARY. Callers can use CC_FAULT_CANARY_EQUAL
 to check fault_canary_out against CCRSA_PSS_FAULT_CANARY.
*/
CC_NONNULL_ALL
int ccrsa_emsa_pss_decode_canary_out_ws(cc_ws_t ws,
                                        const struct ccdigest_info* di,
                                        const struct ccdigest_info* MgfDi,
                                        size_t sSize,
                                        size_t mSize, const uint8_t *mHash,
                                        size_t emBits, const uint8_t *EM,
                                        cc_fault_canary_t fault_canary_out);

/*! @function ccrsa_crt_makekey
 @abstract    Computes dp := d (mod p-1), dq := d (mod q-1), qinv := 1/q (mod p).

 @param fk  Full RSA key with e, p, and q set.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccrsa_crt_makekey(ccrsa_full_ctx_t fk);

CC_NONNULL_ALL
int ccrsa_crt_makekey_ws(cc_ws_t ws, ccrsa_full_ctx_t fk);

/*! @function ccrsa_init_pub_ws

  @abstract   Initialize an RSA public key structure based on modulus and
              exponent. Values are copied into the structure.

  @param ws       Workspace of size CCRSA_INIT_PUB_WORKSPACE_N
  @param pubk     Allocated public key structure (see requirements below)
  @param modulus  cc_unit array of the modulus
  @param e        cc_unit array of the exponent

  @return 0 on success, non-zero on failure. See cc_error.h for more details.

  @discussion ccrsa_ctx_n(pubk) must have been initialized based on the modulus
              size, typically using ccn_nof_size(mod_nbytes). The public key
              structure pubk is typically allocated with
              ccrsa_pub_ctx_decl(mod_nbytes, pubk);
*/
CC_NONNULL_ALL
int ccrsa_init_pub_ws(cc_ws_t ws, ccrsa_pub_ctx_t pubk, const cc_unit *modulus, const cc_unit *e);

/*!
 @function   ccrsa_sign_pkcs1v15_blinded
 @abstract   Same as ccrsa_sign_pkcs1v15, with explicit argument
    for RNG used for blinding

 @param   blinding_rng     Random number generator blinding
 @param      key        Full key
 @param      oid        OID describing the type of digest passed in
 @param      digest_len Byte length of the digest
 @param      digest     Byte array of digest_len bytes containing the digest
 @param      sig_len    Pointer to the number of byte allocate for sig.
 Output the exact size of the signature.
 @param      sig        Pointer to the allocated buffer of size *sig_len
 for the output signature

 @result     0 iff successful.

 @discussion Null OID is a special case, required to support RFC 4346 where the padding
 is based on SHA1+MD5. In general it is not recommended to use a NULL OID,
 except when strictly required for interoperability

 */
CC_NONNULL((1, 2, 5, 6, 7))
int ccrsa_sign_pkcs1v15_blinded(struct ccrng_state *blinding_rng,
                        ccrsa_full_ctx_t key, const uint8_t *oid,
                        size_t digest_len, const uint8_t *digest,
                        size_t *sig_len, uint8_t *sig);

CC_NONNULL((1, 2, 3, 6, 7, 8))
int ccrsa_sign_pkcs1v15_blinded_ws(cc_ws_t ws,
                                   struct ccrng_state *blinding_rng,
                                   ccrsa_full_ctx_t key, const uint8_t *oid,
                                   size_t digest_len, const uint8_t *digest,
                                   size_t *sig_len, uint8_t *sig);

/*!
 @function   ccrsa_sign_pss_blinded
 @abstract   Same as ccrsa_sign_pss, with explicit argument
        for RNG used for blinding

 * @param   blinding_rng     Random number generator blinding
 * @param	key              The RSA key
 * @param	hashAlgorithm    The hash algorithm used to generate mHash from the original message. It is also used inside the PSS encoding function. This is also the hash function to be used in the mask generation function (MGF)
 * @param   MgfHashAlgorithm The hash algorithm for thr mask generation function
 * @param   rng              Random number geberator to generate salt in PSS encoding
 * @param	saltSize          Intended length of the salt
 * @param   hSize             Length of message hash . Must be equal to hashAlgorithm->output_size
 * @param	mHash            The input that needs to be signed. This is the hash of message M with length of hLen
 *
 * @param   sig              The signature output
 * @param   sigSize           The length of generated signature in bytes, which equals the size of the RSA modulus.
 * @return                   0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((3, 4, 6, 8, 9, 10))
int ccrsa_sign_pss_blinded(
                   struct ccrng_state *blinding_rng,
                   ccrsa_full_ctx_t key,
                   const struct ccdigest_info* hashAlgorithm, const struct ccdigest_info* MgfHashAlgorithm,
                   size_t saltSize, struct ccrng_state *rng,
                   size_t hSize, const uint8_t *mHash,
                   size_t *sigSize, uint8_t *sig);

/* Generate a random nbits sized prime p, guaranteed to be relatively prime to e.
   rng_mr is an RNG instance for Miller-Rabin exclusively. */
CC_NONNULL_ALL
int ccrsa_generate_prime(cc_size nbits, cc_unit *p, const cc_unit *e,
                         struct ccrng_state *rng, struct ccrng_state *rng_mr);

/*! @function ccrsa_is_valid_prime
 @abstract Checks whether a given prime candidate is a valid RSA prime.

 @param np       Number of units for p.
 @param p        Prime candidate p.
 @param ne       Number of units for e.
 @param e        Public exponent e.
 @param mr_depth Number of Miller-Rabin iterations.
 @param rng      RNG for Miller-Rabin primality testing.

 @return 1 if p is valid RSA prime, 0 if it is not. A negative error code otherwise.
 */
CC_NONNULL_ALL
int ccrsa_is_valid_prime(cc_size np, const cc_unit *p,
                         cc_size ne, const cc_unit *e,
                         size_t mr_depth,
                         struct ccrng_state *rng);

// Number of entries to trace during FIPS186 key generation
// Currently, '3072' is specified by the largest 'mod'
// value in the RSA2/KeyGen_186-3 vector test file, but
// 4K keys are expected.
#define CCRSA_FIPS186_TRACE_MAX_KEY_UNITS (ccn_nof(4096))

// Number of ccrsa_fips186_trace objects to supply
#define CCRSA_FIPS186_TRACE_NUM           2

/*
 Supply an array of CCRSA_FIPS186_TRACE_NUM of these objects
 to the supporting functions to receive FIPS186 key generation
 intermediary values.
 */
struct ccrsa_fips186_trace {
    size_t bitlen1;
    size_t bitlen2;
    size_t curr;
    cc_unit xp1[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
    cc_unit xp2[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
    cc_unit p1[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
    cc_unit p2[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
    cc_unit xp[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
    cc_unit p[CCRSA_FIPS186_TRACE_MAX_KEY_UNITS];
};

/*
 Generate a FIPS186-4 standard RSA key, saving the intermediary values.

 This function must only be used for internal testing, and should never be
 called directly outside of those circumstances.
 */
CC_NONNULL((2, 4, 5, 6))
int ccrsa_generate_fips186_key_trace(size_t nbits, ccrsa_full_ctx_t fk,
        size_t e_size, const void *eBytes, struct ccrng_state *rng1,
        struct ccrng_state *rng2, struct ccrsa_fips186_trace *trace);

/*
 Construct RSA key from fix input in conformance with FIPS186-4 standard

 This function must only be used for internal testing, and should never be
 called directly outside of those circumstances.
 */
CC_NONNULL((3, 5, 7, 9, 11, 13, 15, 16))
int ccrsa_make_fips186_key_trace(size_t nbits, const cc_size e_n,
        const cc_unit *e, const cc_size xp1Len, const cc_unit *xp1,
        const cc_size xp2Len, const cc_unit *xp2, const cc_size xpLen,
        const cc_unit *xp, const cc_size xq1Len, const cc_unit *xq1,
        const cc_size xq2Len, const cc_unit *xq2, const cc_size xqLen,
        const cc_unit *xq, ccrsa_full_ctx_t fk, cc_size *np, cc_unit *r_p,
        cc_size *nq, cc_unit *r_q, cc_size *nm, cc_unit *r_m, cc_size *nd,
        cc_unit *r_d, struct ccrsa_fips186_trace *trace);

/*!
@function   ccrsa_make_fips186_key
@abstract   Initialize an RSA full key from explicit inputs necessary for validating conformance to FIPS186-4

@param      nbits size in bits of the key to construct
@param      e_n Size in cc_unit of the public exponent
@param      e      Public exponent  represented in cc_units
@param      xp1_nbytes   Size in byte of the first seed for the construction of p
@param      xp1 First seed for the construction of p
@param      xp2_nbytes   Size in byte of the second seed for the construction of p
@param      xp2 Second seed for the construction of p
@param      xp_nbytes   Size in byte of the large seed for the construction of p
@param      xp large seed for the construction of p
@param      xq1_nbytes   Size in byte of the first seed for the construction of q
@param      xq1 First seed for the construction of q
@param      xq2_nbytes   Size in byte of the second seed for the construction of q
@param      xq2 Second seed for the construction of q
@param      xq_nbytes   Size in byte of the large seed for the construction of q
@param      xq large seed for the construction of q
@param      fk     Allocated context where the output constructed key is stored
@param      np     Pointer to the size in cc_unit of the buffer for the output prime factor p. Updated with actual size.
@param      r_p   Copy of the output prime factor p
@param      nq     Pointer to the size in cc_unit of the buffer for the output prime factor q. Updated with actual size.
@param      r_q   Copy of the output prime factor q
@param      nm     Pointer to the size in cc_unit of the buffer for the output modulus m=p*q. Updated with actual size.
@param      r_m   Copy of the output modulus m=p*q
@param      nd     Pointer to the size in cc_unit of the buffer for the output private exponent d. Updated with actual size.
@param      r_d   Copy of the output private exponent d
@result     0          iff successful.
 
 @discussion
    fk should be allocated using ccrsa_full_ctx_decl_nbits(nbits), fk).
*/
CC_NONNULL_ALL
int ccrsa_make_fips186_key(size_t nbits, const cc_size e_n, const cc_unit *e,
                           const cc_size xp1_nbytes, const cc_unit *xp1,
                           const cc_size xp2_nbytes, const cc_unit *xp2,
                           const cc_size xp_nbytes, const cc_unit *xp,
                           const cc_size xq1_nbytes, const cc_unit *xq1,
                           const cc_size xq2_nbytes, const cc_unit *xq2,
                           const cc_size xq_nbytes, const cc_unit *xq,
                           ccrsa_full_ctx_t fk,
                           cc_size *np, cc_unit *r_p,
                           cc_size *nq, cc_unit *r_q,
                           cc_size *nm, cc_unit *r_m,
                           cc_size *nd, cc_unit *r_d);

/*!
 @function   ccrsa_priv_crypt_blinded_ws
 @abstract   Perform RSA operation with a private key (CRT).

 @param      ws            Workspace
 @param      blinding_rng  A handle to an initialized rng state structure.
 @param      key           A handle an RSA private key.
 @param      out           Output buffer, of size ccrsa_ctx_n(key).
 @param      in            Input buffer, of size ccrsa_ctx_n(key).

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccrsa_priv_crypt_blinded_ws(cc_ws_t ws,
                                struct ccrng_state *blinding_rng,
                                ccrsa_full_ctx_t key,
                                cc_unit *cc_unsafe_indexable out,
                                const cc_unit *cc_unsafe_indexable in);

CC_NONNULL_ALL
int ccrsa_pub_crypt_ws(cc_ws_t ws, ccrsa_pub_ctx_t ctx, cc_unit *r, const cc_unit *s);

CC_NONNULL((1, 2, 5, 7))
int ccrsa_verify_pkcs1v15_digest_ws(cc_ws_t ws,
                                    ccrsa_pub_ctx_t key,
                                    const uint8_t *oid,
                                    size_t digest_len, const uint8_t *digest,
                                    size_t sig_len, const uint8_t *sig,
                                    cc_fault_canary_t fault_canary_out);

/*! @function ccrsa_num_mr_iterations
 @abstract Returns the number of Miller-Rabin iterations required to determine
           with sufficiently high probability that an RSA prime factor
           candidate of size 'pbits' is likely prime.

 @discussion As per FIPS 186-4/5. See the source file for more details on the
             algorithms used to determine the number of MR iterations and
             equivalent security strengths for RSA key pairs.

 @param pbits Number of bits for prime factor candidate p.
 */
size_t ccrsa_num_mr_iterations(size_t pbits);

/*! @function ccrsa_num_mr_iterations_aux
 @abstract Returns the number of Miller-Rabin iterations required to determine
           with sufficiently high probability that an RSA auxiliary prime
           candidate of size 'pbits' is likely prime.

 @discussion As per FIPS 186-4/5. See the source file for more details on the
             algorithms used to determine the number of MR iterations and
             equivalent security strengths for RSA key pairs.

 @param pbits Number of bits for auxiliary prime candidate p.
 */
size_t ccrsa_num_mr_iterations_aux(size_t pbits);

CC_NONNULL_ALL
int ccrsa_oaep_encode_parameter_ws(cc_ws_t ws,
                                   const struct ccdigest_info* di,
                                   struct ccrng_state *rng,
                                   size_t r_size, cc_unit *r,
                                   size_t message_len,
                                   const uint8_t *message,
                                   size_t parameter_data_len,
                                   const uint8_t *parameter_data);

CC_NONNULL_ALL
int ccrsa_oaep_decode_parameter_ws(cc_ws_t ws,
                                   const struct ccdigest_info* di,
                                   size_t *r_len, uint8_t *r,
                                   size_t s_size, cc_unit* s,
                                   size_t parameter_data_len,
                                   const uint8_t *parameter_data);

CC_NONNULL((1, 2, 3, 4, 5, 6, 8))
int ccrsa_encrypt_oaep_ws(cc_ws_t ws,
                          ccrsa_pub_ctx_t key,
                          const struct ccdigest_info* di,
                          struct ccrng_state *rng,
                          size_t *r_size, uint8_t *r,
                          size_t s_size, const uint8_t *s,
                          size_t parameter_data_len,
                          const uint8_t *parameter_data);

CC_NONNULL_ALL
int ccrsa_encrypt_eme_pkcs1v15_ws(cc_ws_t ws,
                                  ccrsa_pub_ctx_t key,
                                  struct ccrng_state *rng,
                                  size_t *r_size, uint8_t *r,
                                  size_t s_size, const uint8_t *s);

CC_NONNULL_ALL
int ccrsa_priv_crypt_ws(cc_ws_t ws,
                        ccrsa_full_ctx_t key,
                        cc_unit *out, const cc_unit *in);

/*!
 @function   ccrsa_priv_crypt_blinded
 @abstract   Perform RSA operation with a private key (CRT)
 Clients should use ccn_read_uint() to
 convert bytes to a cc_unit to use for this function.

 @param      blinding_rng        A handle to an initialized rng state structure.
 @param      key        A handle an RSA private key.
 @param      out        Output buffer, of size ccrsa_ctx_n(key).
 @param      in         Input buffer, of size ccrsa_ctx_n(key).

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccrsa_priv_crypt_blinded(struct ccrng_state *blinding_rng,
                             ccrsa_full_ctx_t key,
                             cc_unit *out,
                             const cc_unit *in);

CC_NONNULL_ALL
int ccrsa_priv_crypt_blinded_ws(cc_ws_t ws,
                                struct ccrng_state *blinding_rng,
                                ccrsa_full_ctx_t key,
                                cc_unit *out,
                                const cc_unit *in);

/*!
 @function   ccrsa_decrypt_oaep_blinded_ws

 @abstract   Same as ccrsa_decrypt_oaep, with an explicit RNG for blinding

 @param      ws         Workspace
 @param      blinding_rng        A handle to an initialized rng state structure.
 @param      key        A private key to use to decrypt the package.
 @param      di         A descriptor for the digest used to encode the package.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      c_size     Source (PKCS1 EME Payload) length.
 @param      c          Source buffer to be decoded.
 @param      parameter_data_len Length of tag data (optional)
 @param      parameter_data Pointer to tag data (optional)

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 5, 6, 8))
int ccrsa_decrypt_oaep_blinded_ws(cc_ws_t ws,
                                  struct ccrng_state *blinding_rng,
                                  ccrsa_full_ctx_t key,
                                  const struct ccdigest_info* di,
                                  size_t *r_size, uint8_t *r,
                                  size_t c_size, const uint8_t *c,
                                  size_t parameter_data_len,
                                  const uint8_t *parameter_data);

/*!
 @function   ccrsa_decrypt_eme_pkcs1v15_blinded_ws

 @abstract   Same as ccrsa_decrypt_eme_pkcs1v15, with an explicit RNG for blinding

 @param      blinding_rng        A handle to an initialized rng state structure.
 @param      key        A private key to use to decrypt the package.
 @param      r_size     (In/Out) Result buffer size.
 @param      r          Result buffer.
 @param      s_size     Source (PKCS1 EME Payload) length.
 @param      s          Source buffer to be decoded.

 @return     0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int ccrsa_decrypt_eme_pkcs1v15_blinded_ws(cc_ws_t ws,
                                          struct ccrng_state *blinding_rng,
                                          ccrsa_full_ctx_t key,
                                          size_t *r_size, uint8_t *r,
                                          size_t s_size, const uint8_t *s);

#endif // _CORECRYPTO_CCRSA_INTERNAL_H_
