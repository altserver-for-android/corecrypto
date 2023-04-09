/* Copyright (c) (2015,2016,2018-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_macros.h"

static int ccrsa_verify_pss_digest_ws(cc_ws_t ws,
                                      ccrsa_pub_ctx_t key,
                                      const struct ccdigest_info *di,
                                      const struct ccdigest_info *mgfdi,
                                      size_t digestSize,
                                      const uint8_t *digest,
                                      size_t sigSize,
                                      const uint8_t *sig,
                                      size_t saltSize,
                                      cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }
    cc_fault_canary_t fault_canary;
    CC_FAULT_CANARY_CLEAR(fault_canary);

    const cc_size modBits = cczp_bitlen(ccrsa_ctx_zm(key));
    const cc_size modBytes = cc_ceiling(modBits, 8);
    const cc_size emBits = modBits - 1; // as defined in §8.1.1
    const cc_size emSize = cc_ceiling(emBits, 8);
    int rc = 0;

    // 1.
    if (modBytes != sigSize)
        return CCRSA_INVALID_INPUT;
    if (digestSize != di->output_size)
        return CCRSA_INVALID_INPUT;
    if (modBytes == 0)
        return CCRSA_KEY_ERROR;

    CC_DECL_BP_WS(ws, bp);
    const cc_size n = ccrsa_ctx_n(key);

    // 2.
    // EM is large enough to fit sig variable
    cc_unit *EM = CC_ALLOC_WS(ws, n);

    // 2.a read sig to tmp array and make sure it fits
    cc_require_action(ccn_read_uint(n, EM, sigSize, sig) == 0, errOut, rc = CCRSA_INVALID_INPUT);

    // 2.b
    cc_require((rc = ccrsa_pub_crypt_ws(ws, key, EM, EM)) == 0, errOut);

    // 2.c
    ccn_swap(n, EM);

    // 3
    const size_t ofs = ccn_sizeof_n(n) - emSize;
    cc_assert(ofs <= sizeof(cc_unit)); // make sure sizes are consistent and we don't overrun buffers.
    rc |= ccrsa_emsa_pss_decode_canary_out_ws(ws, di, mgfdi, saltSize, digestSize, digest, emBits, (uint8_t *)EM + ofs, fault_canary);

    if (rc == 0) {
        rc = CCERR_VALID_SIGNATURE;
    } else {
        rc = CCERR_INVALID_SIGNATURE;
    }

    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsa_verify_pss_digest(ccrsa_pub_ctx_t key,
                            const struct ccdigest_info *di,
                            const struct ccdigest_info *mgfdi,
                            size_t digestSize,
                            const uint8_t *digest,
                            size_t sigSize,
                            const uint8_t *sig,
                            size_t saltSize,
                            cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_VERIFY_PSS_DIGEST_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_verify_pss_digest_ws(ws, key, di, mgfdi, digestSize, digest, sigSize, sig, saltSize, fault_canary_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccrsa_verify_pss_msg(ccrsa_pub_ctx_t key,
                         const struct ccdigest_info *di,
                         const struct ccdigest_info *mgfdi,
                         size_t msg_nbytes,
                         const uint8_t *msg,
                         size_t sig_nbytes,
                         const uint8_t *sig,
                         size_t salt_nbytes,
                         cc_fault_canary_t fault_canary_out)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t digest[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, msg_nbytes, msg, digest);
    return ccrsa_verify_pss_digest(key, di, mgfdi, di->output_size, digest, sig_nbytes, sig, salt_nbytes, fault_canary_out);
}
