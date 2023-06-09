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

#include "cc_log.h"

#if CC_LOG

#include <os/once_private.h>

static void
cc_log_init(void *p)
{
    os_log_t *logp = p;
    *logp = os_log_create("com.apple.corecrypto", "default");
}

os_log_t
cc_log_default(void)
{
    static os_log_t log;
    static os_once_t initp;
    os_once(&initp, &log, cc_log_init);
    return log;
}

#endif // CC_LOG
