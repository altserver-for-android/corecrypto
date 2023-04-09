/* Copyright (c) (2011,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include "ccmode_internal.h"

/* Multiply the tweak by alpha (LFSR shift) */
void ccmode_xts_mult_alpha(cc_unit *inTweak) {
    uint8_t *tweak = (uint8_t *)inTweak;
    uint8_t t;

    for (size_t x = t = 0; x < 16; ++x) {
        uint8_t tt = tweak[x] >> 7;
        tweak[x] = ((tweak[x] << 1) | t) & 0xFF;
        t = tt;
    }
    if (t) {
        tweak[0] ^= 0x87;
    }
}