/* Copyright (c) (2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSHA1_INTERNAL_H_
#define _CORECRYPTO_CCSHA1_INTERNAL_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_config.h>

extern const uint32_t ccsha1_initial_state[5];

#if CCSHA1_VNG_INTEL && defined(__x86_64__)
extern const struct ccdigest_info ccsha1_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha1_vng_intel_AVX1_di;
#endif

#endif /* _CORECRYPTO_CCSHA1_INTERNAL_H_ */
