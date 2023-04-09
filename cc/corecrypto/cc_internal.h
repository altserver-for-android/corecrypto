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

#ifndef _CORECRYPTO_CC_INTERNAL_H_
#define _CORECRYPTO_CC_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>

#include <corecrypto/cc_priv.h>

#define cc_ctx_decl_vla(_type_, _size_, _name_) \
  _type_ _name_ [cc_ctx_n(_type_, _size_)]

extern bool cc_rdrand(uint64_t *rand);

#if CC_DIT_SUPPORTED

CC_INLINE bool cc_is_dit_enabled(void)
{
    return __builtin_arm_rsr64("DIT") == (1U << 24);
}

CC_INLINE bool cc_enable_dit(void)
{
     // DIT might have already been enabled by another corecrypto function, in
     // that case that function is responsible for disabling DIT when returning.
     //
     // This also covers when code _outside_ corecrypto enabled DIT before
     // calling us. In that case we're not responsible for disabling it either.
     if (cc_is_dit_enabled()) {
         return false;
     }

     // Enable DIT.
     __builtin_arm_wsr64("DIT", 1);

     // Check that DIT was enabled.
     cc_try_abort_if(!cc_is_dit_enabled(), "DIT not enabled");

     // To the cleanup function, indicate that we toggled DIT and
     // that cc_disable_dit() should actually disable it again.
     return true;
}

void cc_disable_dit(volatile bool *dit_was_enabled);

#define CC_ENSURE_DIT_ENABLED                    \
    volatile bool _cc_dit_auto_disable           \
        __attribute__((cleanup(cc_disable_dit))) \
        __attribute__((unused)) = cc_enable_dit();

#else

#define CC_ENSURE_DIT_ENABLED

#endif // CC_DIT_SUPPORTED

#endif // _CORECRYPTO_CC_INTERNAL_H_
