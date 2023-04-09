/* Copyright (c) (2019,2020,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#ifndef _CORECRYPTO_CC_LOG_H_
#define _CORECRYPTO_CC_LOG_H_

#include "cc_internal.h"

#if CC_LOG
#include <TargetConditionals.h>
#include <os/log.h>

os_log_t cc_log_default(void);

#define CC_LOG_DEFAULT (cc_log_default())

#define cc_log_fault(...)                       \
    os_log_fault(CC_LOG_DEFAULT, __VA_ARGS__)

#define cc_log_fault_if(cond, ...)              \
    do {                                        \
        if (CC_UNLIKELY(cond)) {                \
            cc_log_fault(__VA_ARGS__);          \
        }                                       \
    } while (0)

#else
#define cc_log_fault(...)
#define cc_log_fault_if(...)
#endif // CC_LOG

#endif /* _CORECRYPTO_CC_LOG_H_ */
