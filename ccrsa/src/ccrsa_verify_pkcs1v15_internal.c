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

#include "ccrsa_internal.h"
#include "cc_macros.h"

int ccrsa_verify_pkcs1v15_internal_ws(cc_ws_t ws,
                                      ccrsa_pub_ctx_t key,
                                      const uint8_t *oid,
                                      size_t digest_len,
                                      const uint8_t *digest,
                                      size_t sig_len,
                                      const uint8_t *sig,
                                      int sig_len_validation,
                                      cc_fault_canary_t fault_canary_out)
{
    CC_FAULT_CANARY_CLEAR(fault_canary_out);
    cc_size n = ccrsa_ctx_n(key);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *s = CC_ALLOC_WS(ws, n);

    size_t m_size = ccn_write_uint_size(n, ccrsa_ctx_m(key));
    uint8_t *em = NULL;
    int err;
    int sig_len_valid;

    switch (sig_len_validation) {
    case CCRSA_SIG_LEN_VALIDATION_ALLOW_SHORT_SIGS:
        sig_len_valid = sig_len <= m_size;
        break;
    default:
        sig_len_valid = sig_len == m_size;
        break;
    }

    cc_require_action(sig_len_valid, errOut, err = CCRSA_INVALID_INPUT);

    // Public key operation
    cc_require_action(ccn_read_uint(n, s, sig_len, sig) == 0, errOut, err = CCRSA_INVALID_INPUT);

    cc_require((err = ccrsa_pub_crypt_ws(ws, key, s, s)) == 0, errOut);

    // Prepare data for encoding verification
    ccn_swap(n, s);
    em = (unsigned char *)s + (ccn_sizeof_n(n) - m_size);

    // Encoding verification
    err = ccrsa_emsa_pkcs1v15_verify_canary_out(m_size, em, digest_len, digest, oid, fault_canary_out);
    if (err == 0) {
        err = CCERR_VALID_SIGNATURE;
    } else {
        err = CCERR_INVALID_SIGNATURE;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return err;
}

int ccrsa_verify_pkcs1v15_internal(ccrsa_pub_ctx_t key,
                                   const uint8_t *oid,
                                   size_t digest_len,
                                   const uint8_t *digest,
                                   size_t sig_len,
                                   const uint8_t *sig,
                                   int sig_len_validation,
                                   cc_fault_canary_t fault_canary_out)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PKCS1V15_INTERNAL_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pkcs1v15_internal_ws(ws, key, oid, digest_len, digest, sig_len, sig, sig_len_validation, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}
