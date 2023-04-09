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

#ifndef _CORECRYPTO_CCSAE_INTERNAL_H_
#define _CORECRYPTO_CCSAE_INTERNAL_H_

#include "cc_memory.h"

extern const char *SAE_KCK_PMK_LABEL;              // = "SAE KCK and PMK";
extern const char *SAE_HUNT_PECK_LABEL;            // = "SAE Hunting and Pecking";
extern const uint8_t SAE_HUNT_AND_PECK_ITERATIONS; // = 40;

extern const uint8_t CCSAE_STATE_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_UPDATE;
extern const uint8_t CCSAE_STATE_COMMIT_GENERATED;
extern const uint8_t CCSAE_STATE_COMMIT_VERIFIED;
extern const uint8_t CCSAE_STATE_COMMIT_BOTH;
extern const uint8_t CCSAE_STATE_CONFIRMATION_GENERATED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_VERIFIED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_BOTH;

/*! @function ccsae_y2_from_x_ws
 @abstract Generates the square of the 'y' coordinate, if it exists, given an `x` coordinate and curve parameters.

 @param cp    ECC parameters
 @param ws    Workspace of size CCSAE_Y2_FROM_X_WORKSPACE_N(ccec_cp_n(cp))
 @param y2    Output 'y^2'
 @param x_in  Input 'x' coordinate

 @return true on success, false on failure.
 */
bool ccsae_y2_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *y2, const cc_unit *x_in);


#endif // _CORECRYPTO_CCSAE_INTERNAL_H_
