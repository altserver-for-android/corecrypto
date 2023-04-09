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
#include "cc_macros.h"
#include "ccmode_internal.h"
#include <corecrypto/ccmode.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccsigma_priv.h>
#include <corecrypto/ccsigma_mfi.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccnistkdf.h>

CC_IGNORE_VLA_WARNINGS

static ccec_full_ctx_t mfi_kex_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->key_exchange.ctx;
}

static ccec_pub_ctx_t mfi_peer_kex_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->key_exchange.peer_ctx;
}

static ccec_full_ctx_t mfi_sign_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->signature.ctx;
}

static ccec_pub_ctx_t mfi_peer_sign_ctx(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->signature.peer_ctx;
}

static void *mfi_session_keys_buffer(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    return ctx->session_keys_buffer;
}

static int mfi_session_keys_derive(struct ccsigma_ctx *ctx,
                                   size_t shared_secret_size,
                                   const void *shared_secret,
                                   size_t transcript_size,
                                   const void *transcript)
{
    size_t key_share_size = ccec_compressed_x962_export_pub_size(ctx->info->key_exchange.curve_params);
    size_t kdf_ctx_size = 1 + (2 * key_share_size) + transcript_size;
    uint8_t kdf_ctx[kdf_ctx_size];

    // SHA256('MFi 4.0 SIGMA-I Authentication Randomness Extraction')[:16]
    const uint8_t salt[] = {
        0xb6, 0x3f, 0xd4, 0x30, 0x48, 0x2f, 0x6d, 0x50,
        0x62, 0x41, 0x99, 0xe9, 0x88, 0x81, 0xb1, 0xf6,
    };

    uint8_t kdk[16];
    int err = cccmac_one_shot_generate(ccaes_cbc_encrypt_mode(),
                                       sizeof(salt), salt,
                                       shared_secret_size, shared_secret,
                                       sizeof(kdk), kdk);
    cc_require(err == CCERR_OK, out);

    // domain-separation tag
    kdf_ctx[0] = 0x1;

    uint8_t *p = kdf_ctx + 1;

    err = ccec_compressed_x962_export_pub(ccsigma_kex_init_ctx(ctx), p);
    cc_require(err == CCERR_OK, out);

    p += key_share_size;

    err = ccec_compressed_x962_export_pub(ccsigma_kex_resp_ctx(ctx), p);
    cc_require(err == CCERR_OK, out);

    p += key_share_size;

    cc_memcpy(p, transcript, transcript_size);

    // "MFi 4.0 SIGMA-I Authentication Key Expansion"
    const uint8_t label[] = {
        0x4d, 0x46, 0x69, 0x20, 0x34, 0x2e, 0x30, 0x20,
        0x53, 0x49, 0x47, 0x4d, 0x41, 0x2d, 0x49, 0x20,
        0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4b,
        0x65, 0x79, 0x20, 0x45, 0x78, 0x70, 0x61, 0x6e,
        0x73, 0x69, 0x6f, 0x6e,
    };
    err = ccnistkdf_ctr_cmac(ccaes_cbc_encrypt_mode(),
                             32,
                             sizeof(kdk), kdk,
                             sizeof(label), label,
                             kdf_ctx_size, kdf_ctx,
                             ctx->info->session_keys.buffer_size,
                             4,
                             ctx->info->session_keys.buffer(ctx));

 out:
    return err;
}

static int mfi_mac_compute(struct ccsigma_ctx *ctx,
                           size_t key_size,
                           const void *key,
                           size_t data_size,
                           const void *data,
                           void *mac)
{
    return cccmac_one_shot_generate(ccaes_cbc_encrypt_mode(),
                                    key_size,
                                    key,
                                    data_size,
                                    data,
                                    ctx->info->mac.tag_size,
                                    mac);
}

static int mfi_sigma_compute_mac_and_digest(struct ccsigma_ctx *ctx,
                                            ccsigma_role_t role,
                                            size_t identity_size,
                                            const void *identity,
                                            void *digest)
{
    const struct ccdigest_info *digest_info = ctx->info->signature.digest_info;
    ccdigest_di_decl(digest_info, digest_ctx);

    ccdigest_init(digest_info, digest_ctx);

    uint8_t dst = 0x1;
    ccdigest_update(digest_info, digest_ctx, sizeof(dst), &dst);

    size_t key_share_size = ccec_compressed_x962_export_pub_size(ctx->info->key_exchange.curve_params);
    uint8_t key_share[key_share_size];

    ccec_pub_ctx_t init_kex_ctx = ccsigma_kex_init_ctx(ctx);
    ccec_compressed_x962_export_pub(init_kex_ctx, key_share);
    ccdigest_update(digest_info, digest_ctx, key_share_size, key_share);

    ccec_pub_ctx_t resp_kex_ctx = ccsigma_kex_resp_ctx(ctx);
    ccec_compressed_x962_export_pub(resp_kex_ctx, key_share);
    ccdigest_update(digest_info, digest_ctx, key_share_size, key_share);

    uint8_t tag[ctx->info->mac.tag_size];
    size_t key_index = ctx->info->sigma.mac_key_indices[role];

    int err = ccsigma_compute_mac(ctx, key_index, identity_size, identity, tag);
    cc_require(err == CCERR_OK, out);

    ccdigest_update(digest_info, digest_ctx, ctx->info->mac.tag_size, tag);

    ccdigest_final(digest_info, digest_ctx, digest);

 out:
    return err;
}

static int mfi_aead_seal(struct ccsigma_ctx *ctx,
                         size_t key_size,
                         const void *key,
                         size_t iv_size,
                         const void *iv,
                         size_t add_data_size,
                         const void *add_data,
                         size_t ptext_size,
                         const void *ptext,
                         void *ctext,
                         void *tag)
{
    return ccccm_one_shot(ccaes_ccm_encrypt_mode(),
                          key_size,
                          key,
                          iv_size,
                          iv,
                          ptext_size,
                          ptext,
                          ctext,
                          add_data_size,
                          add_data,
                          ctx->info->aead.tag_size,
                          tag);
}

static int mfi_aead_open(struct ccsigma_ctx *ctx,
                         size_t key_size,
                         const void *key,
                         size_t iv_size,
                         const void *iv,
                         size_t add_data_size,
                         const void *add_data,
                         size_t ptext_size,
                         const void *ptext,
                         void *ctext,
                         void *tag)
{
    uint8_t computed_tag[ctx->info->aead.tag_size];
    int err = ccccm_one_shot(ccaes_ccm_decrypt_mode(),
                             key_size,
                             key,
                             iv_size,
                             iv,
                             ptext_size,
                             ptext,
                             ctext,
                             add_data_size,
                             add_data,
                             ctx->info->aead.tag_size,
                             computed_tag);
    cc_require(err == CCERR_OK, out);

    if (cc_cmp_safe(ctx->info->aead.tag_size, tag, computed_tag)) {
        err = CCERR_INTEGRITY;
    }

 out:
    return err;
}

static void mfi_aead_next_iv(size_t iv_size, void *iv)
{
    inc_uint(iv, iv_size);
}

static void mfi_clear(struct ccsigma_ctx *sigma_ctx)
{
    struct ccsigma_mfi_ctx *ctx = (struct ccsigma_mfi_ctx *)sigma_ctx;
    cc_clear(sizeof(*ctx), ctx);
}

const static size_t mfi_session_keys_info[CCSIGMA_MFI_SESSION_KEYS_COUNT] = {
    16, // CCSIGMA_MFI_ER_KEY
    12, // CCSIGMA_MFI_ER_IV
    16, // CCSIGMA_MFI_TR_KEY
    16, // CCSIGMA_MFI_CR_KEY
    12, // CCSIGMA_MFI_CR_IV
    16, // CCSIGMA_MFI_SR_KEY
    12, // CCSIGMA_MFI_SR_IV
    16, // CCSIGMA_MFI_EI_KEY
    12, // CCSIGMA_MFI_EI_IV
    16, // CCSIGMA_MFI_TI_KEY
    16, // CCSIGMA_MFI_CI_KEY
    12, // CCSIGMA_MFI_CI_IV
    16, // CCSIGMA_MFI_SI_KEY
    12, // CCSIGMA_MFI_SI_IV
};

static struct ccsigma_info mfi_info;

const struct ccsigma_info *ccsigma_mfi_info(void)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_cp_256();

    cc_assert(CCSIGMA_MFI_KEX_CP_BITSIZE == ccec_cp_prime_bitlen(cp));

    mfi_info.key_exchange.curve_params = cp;
    mfi_info.key_exchange.ctx = mfi_kex_ctx;
    mfi_info.key_exchange.peer_ctx = mfi_peer_kex_ctx;

    ccec_pub_ctx_decl_cp(cp, dummy);
    ccec_ctx_init(cp, dummy);
    size_t signature_size = 2 * ccec_signature_r_s_size(dummy);

    cc_assert(CCSIGMA_MFI_SIG_CP_SIZE == ccec_cp_prime_size(cp));
    cc_assert(CCSIGMA_MFI_SIG_CP_BITSIZE == ccec_cp_prime_bitlen(cp));
    cc_assert(CCSIGMA_MFI_SIGNATURE_SIZE == signature_size);

    mfi_info.signature.curve_params = cp;
    mfi_info.signature.digest_info = ccsha256_di();
    mfi_info.signature.signature_size = signature_size;
    mfi_info.signature.ctx = mfi_sign_ctx;
    mfi_info.signature.peer_ctx = mfi_peer_sign_ctx;

    mfi_info.session_keys.count = CCSIGMA_MFI_SESSION_KEYS_COUNT;
    mfi_info.session_keys.info = mfi_session_keys_info;
    mfi_info.session_keys.buffer_size = CCSIGMA_MFI_SESSION_KEYS_BUFFER_SIZE;
    mfi_info.session_keys.buffer = mfi_session_keys_buffer;
    mfi_info.session_keys.derive = mfi_session_keys_derive;

    mfi_info.mac.tag_size = CCSIGMA_MFI_MAC_TAG_SIZE;
    mfi_info.mac.compute = mfi_mac_compute;

    mfi_info.sigma.mac_key_indices[0] = CCSIGMA_MFI_TI_KEY;
    mfi_info.sigma.mac_key_indices[1] = CCSIGMA_MFI_TR_KEY;
    mfi_info.sigma.compute_mac_and_digest = mfi_sigma_compute_mac_and_digest;

    mfi_info.aead.tag_size = CCSIGMA_MFI_AEAD_TAG_SIZE;
    mfi_info.aead.seal = mfi_aead_seal;
    mfi_info.aead.open = mfi_aead_open;
    mfi_info.aead.next_iv = mfi_aead_next_iv;

    mfi_info.clear = mfi_clear;
    return &mfi_info;
}

CC_RESTORE_VLA_WARNINGS
