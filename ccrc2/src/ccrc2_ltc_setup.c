/* Copyright (c) (2010-2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/**********************************************************************\
* To commemorate the 1996 RSA Data Security Conference, the following  *
* code is released into the public domain by its author.  Prost!       *
*                                                                      *
* This cipher uses 16-bit words and little-endian byte ordering.       *
* I wonder which processor it was optimized for?                       *
*                                                                      *
* Thanks to CodeView, SoftIce, and D86 for helping bring this code to  *
* the public.                                                          *
\**********************************************************************/

#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_error.h>
#include "cc_macros.h"
#include <corecrypto/ccrc2.h>
#include "ltc_rc2.h"

/* 256-entry permutation table, probably derived somehow from pi */
static const unsigned char permute[256] = {
        217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
        198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
         23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
        189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
         84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
         18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
        111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
        248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
          8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
        150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
        194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
        153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
         45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
        211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
         13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
        197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};

 /*!
    Initialize the LTC_RC2 block cipher
    @param ecb Unused
    @param skey The key in as scheduled by this function
    @param key_nbytes The key length in bytes
    @param key The symmetric key you wish to pass
 */
int ccrc2_ltc_setup(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *skey, size_t key_nbytes, const void *key)
{
    int ret = CCERR_PARAMETER;
    ltc_rc2_keysched *rc2;
    uint32_t *xkey;
    uint8_t tmp[128] = { 0 };
    uint32_t T8, TM;
    size_t i, bits;

    rc2 = (ltc_rc2_keysched *)skey;

    xkey = rc2->xkey;

    cc_require(key_nbytes >= 1 && key_nbytes <= 128, cleanup);
    cc_memcpy(tmp, key, key_nbytes);

    /* Phase 1: Expand input key to 128 bytes */
    for (i = key_nbytes; i < 128; i++) {
        tmp[i] = permute[(tmp[i - 1] + tmp[i - key_nbytes]) & 0xff];
    }

    /* Phase 2 - reduce effective key size to "bits" */
    bits = key_nbytes<<3;
    T8   = (uint32_t)((bits+7)>>3);
    TM   = (uint32_t)(255 >> (7 & -bits));
    tmp[128 - T8] = permute[tmp[128 - T8] & TM];
    for (i = 128 - T8; i-- > 0;) {
        tmp[i] = permute[tmp[i + 1] ^ tmp[i + T8]];
    }

    /* Phase 3 - copy to xkey in little-endian order */
    for (i = 0; i < 64; i++) {
        xkey[i] =  (uint32_t)tmp[2*i] + ((uint32_t)tmp[2*i+1] << 8);
    }

    ret = CCERR_OK;

 cleanup:
    cc_clear(sizeof(tmp),tmp);

    return ret;
}
