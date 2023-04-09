/* Copyright (c) (2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* Autogenerated file - Use scheme ccdh_gen_gp to regenerate */
#include "ccdh_internal.h"
#include <corecrypto/ccsrp_gp.h>

static ccdh_gp_decl_static(2048) _ccsrp_gp_rfc5054_2048 =
{
    .hp = {
        .n = ccn_nof(2048),
        .bitlen = 2048,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .p = {
        /* prime */
        CCN64_C(0f,a7,11,1f,9e,4a,ff,73),CCN64_C(9b,65,e3,72,fc,d6,8e,f2),
        CCN64_C(35,de,23,6d,52,5f,54,75),CCN64_C(94,b5,c8,03,d8,9f,7a,e4),
        CCN64_C(71,ae,35,f8,e9,db,fb,b6),CCN64_C(2a,56,98,f3,a8,d0,c3,82),
        CCN64_C(9c,cc,04,1c,7b,c3,08,d8),CCN64_C(af,87,4e,73,03,ce,53,29),
        CCN64_C(61,60,27,90,04,e5,7a,e6),CCN64_C(03,2c,fb,db,f5,2f,b3,78),
        CCN64_C(5e,a7,7a,27,75,d2,ec,fa),CCN64_C(54,45,23,b5,24,b0,d5,7d),
        CCN64_C(5b,9d,32,e6,88,f8,77,48),CCN64_C(f1,d2,b9,07,87,17,46,1a),
        CCN64_C(76,bd,20,7a,43,6c,64,81),CCN64_C(ca,97,b4,3a,23,fb,80,16),
        CCN64_C(1d,28,1e,44,6b,14,77,3b),CCN64_C(73,59,d0,41,d5,c3,3e,a7),
        CCN64_C(a8,0d,74,0a,db,f4,ff,74),CCN64_C(55,f9,79,93,ec,97,5e,ea),
        CCN64_C(29,18,a9,96,2f,0b,93,b8),CCN64_C(66,1a,05,fb,d5,fa,aa,e8),
        CCN64_C(cf,60,95,17,9a,16,3a,b3),CCN64_C(e8,08,39,69,ed,b7,67,b0),
        CCN64_C(cd,7f,48,a9,da,04,fd,50),CCN64_C(d5,23,12,ab,4b,03,31,0d),
        CCN64_C(81,93,e0,75,77,67,a1,3d),CCN64_C(a3,73,29,cb,b4,a0,99,ed),
        CCN64_C(fc,31,92,94,3d,b5,60,50),CCN64_C(af,72,b6,65,19,87,ee,07),
        CCN64_C(f1,66,de,5e,13,89,58,2f),CCN64_C(ac,6b,db,41,32,4a,9a,9b)
    },
    .recip = {
        /* recip */
        CCN64_C(27,df,7a,2a,62,1e,90,fc),CCN64_C(29,02,f5,4e,9c,68,a9,71),
        CCN64_C(41,a1,a0,7a,46,a1,77,a2),CCN64_C(b7,fe,ee,30,a9,e0,00,8d),
        CCN64_C(c6,71,2a,f8,09,5a,21,82),CCN64_C(61,3c,33,1e,09,c4,be,79),
        CCN64_C(5d,3c,74,14,d6,a7,c2,8f),CCN64_C(c2,ba,0c,6e,39,26,17,d8),
        CCN64_C(5d,76,88,e3,96,48,f4,55),CCN64_C(27,6f,40,bc,00,c8,f9,63),
        CCN64_C(10,79,de,a9,af,29,5f,7f),CCN64_C(0e,5f,8a,37,b6,f4,15,dd),
        CCN64_C(24,04,39,a7,25,82,68,e3),CCN64_C(6b,a1,03,d2,58,85,c3,6d),
        CCN64_C(9f,65,b6,a9,95,a3,68,dc),CCN64_C(34,09,82,b8,da,99,16,49),
        CCN64_C(16,b4,dd,cd,47,00,93,76),CCN64_C(19,82,94,4d,d9,30,5c,03),
        CCN64_C(80,6b,86,6c,42,6f,0f,26),CCN64_C(aa,2a,d0,0b,84,f0,07,58),
        CCN64_C(30,b3,c4,af,31,88,a8,47),CCN64_C(32,fe,54,c9,de,ac,49,ac),
        CCN64_C(bd,f5,bc,34,47,57,dc,af),CCN64_C(df,3c,51,20,ae,4f,c7,f9),
        CCN64_C(c6,9f,6b,1b,9f,96,f6,08),CCN64_C(ab,9c,74,6f,c7,07,00,76),
        CCN64_C(86,c9,09,7c,25,82,b1,a6),CCN64_C(ff,80,d8,d0,d2,be,34,a4),
        CCN64_C(8e,9e,50,bc,f7,55,99,db),CCN64_C(50,de,fe,5c,48,0d,35,ac),
        CCN64_C(25,8a,7a,35,11,14,5e,a6),CCN64_C(7c,17,9b,ae,0b,08,53,82),
        CCN8_C(01)
    },
    .g = {
        /* g */
        CCN64_C(00,00,00,00,00,00,00,02),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .q = {
        /* q */
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .l = 256,
};

ccdh_const_gp_t ccsrp_gp_rfc5054_2048(void)
{
    return (ccdh_const_gp_t)&_ccsrp_gp_rfc5054_2048;
}