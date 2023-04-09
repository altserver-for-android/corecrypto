/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef _CORECRYPTO_CCDER_INTERNAL_H_
#define _CORECRYPTO_CCDER_INTERNAL_H_

CC_NONNULL((1, 3)) CC_NODISCARD
bool ccder_blob_decode_tl_internal(ccder_read_blob *from, ccder_tag expected_tag, size_t *lenp, bool strict);

#endif /* _CORECRYPTO_CCDER_INTERNAL_H_ */
