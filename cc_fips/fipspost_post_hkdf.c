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

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchkdf.h>
#include "cc_debug.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_hkdf.h"

#define FIPSPOST_POST_HKDF_DK_NBYTES 32

int fipspost_post_hkdf(CC_UNUSED uint32_t fips_mode)
{
    const struct ccdigest_info *sha1 = ccsha1_di();
    const struct ccdigest_info *sha256 = ccsha256_di();
    const struct ccdigest_info *sha512 = ccsha512_di();

    uint8_t ikm[32] = { 0 };
    uint8_t salt[16] = { 0 };
    uint8_t info[8] = { 0 };
    uint8_t dk[FIPSPOST_POST_HKDF_DK_NBYTES] = { 0 };

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        ikm[0] = 0x01; // Flip a bit
    }

    typedef struct {
        const struct ccdigest_info *digest_info;
        unsigned char *digest_name;
        uint8_t dk[FIPSPOST_POST_HKDF_DK_NBYTES];
    } hkdf_test;

    hkdf_test tests[] = {
        { sha1, (unsigned char *)"sha1", { 0x79, 0x21, 0x9d, 0x02, 0x63, 0x6e, 0xfe, 0xd2, 0xd0, 0xa8, 0x65,
                                           0x2e, 0xee, 0x81, 0x5e, 0x26, 0xf1, 0xfb, 0x50, 0x45, 0x87, 0x2b,
                                           0x31, 0x88, 0x95, 0x46, 0x68, 0xbd, 0x16, 0xbc, 0xee, 0xdf } },
        { sha256, (unsigned char *)"sha256", { 0x9b, 0xb8, 0xd9, 0x4b, 0x81, 0x1c, 0xe4, 0x11, 0x0d, 0x35, 0x81,
                                               0x43, 0x68, 0xb1, 0xbe, 0x5f, 0x63, 0xad, 0x1f, 0x4d, 0xc0, 0xa4,
                                               0x37, 0x2d, 0x1f, 0x3b, 0xdb, 0x16, 0xa8, 0xb9, 0x72, 0xf6 } },
        { sha512, (unsigned char *)"sha512", { 0xb5, 0x0c, 0x08, 0x6f, 0x1b, 0xf8, 0x55, 0x4e, 0x2b, 0x0a, 0x5d,
                                               0xf2, 0x13, 0xbd, 0xbf, 0xad, 0x88, 0x64, 0x15, 0xe3, 0x27, 0x7e,
                                               0xb3, 0xc4, 0x32, 0x56, 0x3d, 0x1b, 0x8f, 0xd4, 0xc7, 0xcb } },
    };

    int status = CCERR_OK;

    for (size_t i = 0; i < sizeof(tests) / sizeof(hkdf_test); i++) {
        hkdf_test *current_test = &(tests[i]);
        cchkdf(current_test->digest_info, sizeof(ikm), ikm, sizeof(salt), salt, sizeof(info), info, sizeof(dk), dk);

        if (cc_cmp_safe(FIPSPOST_POST_HKDF_DK_NBYTES, dk, current_test->dk)) {
            failf("HKDF with digest %s", current_test->digest_name);
            status = CCPOST_KAT_FAILURE;
        }
    }
    return status;
}
