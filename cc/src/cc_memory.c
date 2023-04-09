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

#include "cc_memory.h"
#include <stddef.h>

/* Workspace debugging. */

#if CC_ALLOC_DEBUG
struct ws_dbg {
    const void *p;
    const char *file;
    int line;
    const char *func;
} g_ws_dbg;

void cc_ws_alloc_debug(CC_UNUSED const void *p, CC_UNUSED const char *file, CC_UNUSED int line, CC_UNUSED const char *func)
{
    // Contract for some client is to have a single malloc at a time
    cc_assert(g_ws_dbg.p == NULL);
    g_ws_dbg = (struct ws_dbg){ p, file, line, func };
}

void cc_ws_free_debug(CC_UNUSED const void *p)
{
    // Contract for some client is to have a single malloc at a time
    cc_assert(g_ws_dbg.p == p); // Free the address we allocated
    g_ws_dbg = (struct ws_dbg){};
}
#endif // CC_ALLOC_DEBUG

/* Generic heap malloc() and free() functions. */

#if CC_KERNEL

#include <IOKit/IOLib.h>
#include <vm/pmap.h>

void *cc_malloc_clear(size_t s)
{
    void *p = NULL;
    if (pmap_in_ppl()) {
        if (s > PAGE_SIZE) {
            panic("PPL cc_malloc_clear trying to allocate %zu > PAGE_SIZE", s);
        }

        p = pmap_claim_reserved_ppl_page();
    } else {
        p = IOMallocData(s);
    }
    if (p != NULL) {
        memset(p, 0, s);
    }
    return p;
}

CC_INLINE void cc_free(void *p, size_t size)
{
    if (pmap_in_ppl()) {
        if (size > PAGE_SIZE) {
            panic("PPL cc_malloc_clear trying to free %zu > PAGE_SIZE", size);
        }

        pmap_free_reserved_ppl_page(p);
    } else {
        IOFreeData(p, size);
    }
}

#else // !CC_KERNEL

#include <stdlib.h>

void *cc_malloc_clear(size_t s)
{
    void *p = malloc(s);
    if (p != NULL) {
        memset(p, 0, s);
    }
    return p;
}

CC_INLINE void cc_free(void *p, size_t size CC_UNUSED)
{
    free(p);
}

#endif // !CC_KERNEL

/* Generic workspace functions. */

cc_unit* cc_ws_alloc(cc_ws_t ws, cc_size n)
{
    cc_unit *mem = (cc_unit *)ws->ctx + ws->offset;
    ws->offset += n;
    cc_try_abort_if(ws->offset > ws->nunits, "alloc ws");
    return mem;
}

void cc_ws_clear(cc_ws_t ws)
{
    cc_try_abort_if(ws->offset > ws->nunits, "clear ws");
    ccn_clear(ws->nunits, ws->ctx);
}

void cc_ws_free(cc_ws_t ws)
{
    cc_try_abort_if(ws->offset > ws->nunits, "free ws");
    cc_free(ws->ctx, ccn_sizeof_n(ws->nunits));
    ws->nunits = ws->offset = 0;
    ws->ctx = NULL;
}

/* Stack-based workspace functions. */

void cc_ws_free_stack(cc_ws_t ws)
{
    cc_try_abort_if(ws->offset > ws->nunits, "free ws");
    ws->nunits = ws->offset = 0;
    ws->ctx = NULL;
}
