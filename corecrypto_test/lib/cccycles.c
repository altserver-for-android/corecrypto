/* Copyright (c) (2014-2016,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "cc_macros.h"
#include "cccycles.h"
#include <kperf/kpc.h>
#include <sys/sysctl.h>

#if CC_DARWIN

#if defined(__arm64__) || defined(__arm__)

#define CC_CYCLE_CONFIG (0x2)

#else

#define IA32_EVENT_UNHALTED_CORE_UMASK (0x00)
#define IA32_EVENT_UNHALTED_CORE_EVENT (0x3c)

#define IA32_EVTSEL_EVENT_SHIFT (0)
#define IA32_EVTSEL_UMASK_SHIFT (8)

#define IA32_EVTSEL_USR_MASK (0x10000)
#define IA32_EVTSEL_EN_MASK (0x400000)

#define CC_CYCLE_CONFIG                                             \
    ((IA32_EVENT_UNHALTED_CORE_EVENT << IA32_EVTSEL_EVENT_SHIFT) |  \
     (IA32_EVENT_UNHALTED_CORE_UMASK << IA32_EVTSEL_UMASK_SHIFT) |  \
     IA32_EVTSEL_USR_MASK |                                         \
     IA32_EVTSEL_EN_MASK)

#endif

static int monotonic = 0;

static kpc_config_t *kpc_config;
static uint64_t *kpc_counters;
static uint32_t kpc_counter_count;

static int cc_cycles_init(void)
{
    int status;

    size_t monotonic_size = sizeof(monotonic);
    status = sysctlbyname("kern.monotonic.supported", &monotonic, &monotonic_size, NULL, 0);
    if (status == 0 && monotonic == 1) {
        return status;
    }

    uint32_t config_count = kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
    kpc_config = calloc(config_count, sizeof(kpc_config_t));
    kpc_config[0] = CC_CYCLE_CONFIG;

    status = kpc_set_config(KPC_CLASS_CONFIGURABLE_MASK, kpc_config);
    cc_require_or_return(status == 0, status);

    status = kpc_set_counting(KPC_CLASS_CONFIGURABLE_MASK);
    cc_require_or_return(status == 0, status);

    status = kpc_set_thread_counting(KPC_CLASS_CONFIGURABLE_MASK);
    cc_require_or_return(status == 0, status);

    kpc_counter_count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
    kpc_counters = calloc(kpc_counter_count, sizeof(uint64_t));

    return status;
}

extern int thread_selfcounts(int type, void *buf, size_t nbytes);

uint64_t cc_cycles(int *error)
{
    static bool init = false;

    if (CC_UNLIKELY(!init)) {
        *error = cc_cycles_init();
        cc_require_or_return(*error == 0, 0);

        init = true;
    }

    if (monotonic) {
        uint64_t counts[2];
        *error = thread_selfcounts(1, counts, sizeof(counts));
        return counts[1];
    } else {
        *error = kpc_get_thread_counters(0, kpc_counter_count, kpc_counters);
        return kpc_counters[0];
    }
}

#endif
