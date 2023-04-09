/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_WORKSPACES_H_
#define _CORECRYPTO_CC_WORKSPACES_H_

CC_PURE size_t sizeof_cc_unit(void);

CC_PURE size_t sizeof_struct_cczp(void);

CC_PURE size_t sizeof_struct_ccec_full_ctx(void);

CC_PURE size_t sizeof_struct_ccec_pub_ctx(void);

CC_PURE cc_size CCN_MAKE_RECIP_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCZP_GENERATE_NON_ZERO_ELEMENT_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCZP_GENERATE_RANDOM_ELEMENT_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCDH_POWER_BLINDED_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_DIV_EUCLID_WORKSPACE_N(cc_size na, cc_size nd);

CC_PURE cc_size CCN_DIV_USE_RECIP_WORKSPACE_N(cc_size na, cc_size nd);

CC_PURE cc_size CCRSA_CRT_DIVMOD_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCEC_GENERATE_SCALAR_FIPS_EXTRABITS_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCEC_GENERATE_SCALAR_PKA_WORKSPACE_N(cc_size n, cc_size nk);

CC_PURE cc_size CCZ_EXPMOD_WORKSPACE_N(cc_size n, cc_size nm);

CC_PURE cc_size CCZP_MODN_WORKSPACE_N(cc_size ns, cc_size n);

CC_PURE cc_size CCEC_MULT_DIV_MASK_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCZP_MM_COMPUTE_R1R2_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCZP_POWER_BLINDED_DIV_MASK_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_P224_INV_ASM_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCN_P256_INV_ASM_WORKSPACE_N(cc_size n);

CC_PURE cc_size CCSRP_CLIENT_DIVMOD_WORKSPACE_N(cc_size n);

#include "cc_workspaces_generated.h"

#endif // _CORECRYPTO_CC_WORKSPACES_H_
