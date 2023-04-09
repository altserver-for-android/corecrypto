/* Copyright (c) (2020-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <string.h>
#include <stdio.h>
#include <corecrypto/cc_config.h>
#include <corecrypto/module_id.h>

#if CC_USE_L4
    #include <info.h>
#endif

//
//  Provide string version of the FIPS 140-x Validated corecrypto Module
//
extern const char *cc_module_id(enum cc_module_id_format outformat)
{
    static char moduleID[256] = { 0 };
    const size_t length = sizeof(moduleID);
    static char moduleSecLevel[8] = { 0 };
    const size_t SLlen = sizeof(moduleSecLevel);
    static char moduleProc[16] = { 0 };
    const size_t Prlen = sizeof(moduleProc);
    
#define moduleBaseName "Apple corecrypto Module" 	// Module Base Name
#define moduleVersion "12.0"                    	// 2021 OS Releases

    // snprintf can be a macro, and thus requires the ()

#if defined(__x86_64__) || defined(__i386__)
    (snprintf)(moduleProc, Prlen, "Intel");         // Intel-based Macs
#elif defined(__arm__) || defined(__arm64__)        // Apple ARM/silicon

	#if defined(TARGET_OS_OSX) && (TARGET_OS_OSX)   // macOS on Apple silicon
        (snprintf)(moduleProc, Prlen, "Apple silicon");
    #else
        (snprintf)(moduleProc, Prlen, "Apple ARM");
    #endif
    
	#if CC_USE_L4
        (snprintf)(moduleSecLevel, SLlen, "SL2");
    #endif
#else
    (snprintf)(moduleProc, Prlen, "Undefined SoC"); // Should never reach here, but...
#endif

#if CC_KERNEL
    #define moduleTarget "Kernel"                   // Target Environment
    #define moduleType "Software"                   // Hardware / Software
    (snprintf)(moduleSecLevel, SLlen, "SL1");       // FIPS 140-3 Security Level
#elif !CC_USE_L4
    #define moduleTarget "User"                     // Target Environment
    #define moduleType "Software"                   // Hardware / Software
    (snprintf)(moduleSecLevel, SLlen, "SL1");       // FIPS 140-3 Security Level
#else
    #define moduleTarget "Secure Key Store"			// Target Environment
    #define moduleType "Hardware"					// Hardware / Software
#endif

// Full (default) format:
// <moduleBaseName> v<moduleVersion> [<moduleProc>, <moduleTarget>, <moduleType>, <moduleSecLevel>]
// eg. Apple corecrypto Module v12.0 [Apple Silicon, Secure Key Store, Hardware, SL2]

    switch (outformat) {
    case cc_module_id_Full: {
        (snprintf)(moduleID, length, "%s v%s [%s, %s, %s, %s]", moduleBaseName, moduleVersion, moduleProc, moduleTarget, moduleType, moduleSecLevel);
    } break;
    case cc_module_id_Version:
        (snprintf)(moduleID, length, "%s", moduleVersion);
        break;
    case cc_module_id_Target:
        (snprintf)(moduleID, length, "%s", moduleTarget);
        break;
    case cc_module_id_Proc:
        (snprintf)(moduleID, length, "%s", moduleProc);
        break;
    case cc_module_id_Name:
        (snprintf)(moduleID, length, "%s", moduleBaseName);
        break;
    case cc_module_id_Type:
        (snprintf)(moduleID, length, "%s", moduleType);
        break;
    case cc_module_id_SecLevel:
        (snprintf)(moduleID, length, "%s", moduleSecLevel);
        break;
    default:
        (snprintf)(moduleID, length, "INVALID Module ID");
    }

    return moduleID;
}
