# Copyright (c) (2012,2015,2016,2018-2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCAES_INTEL_ASM && (defined __i386__ || defined __x86_64__)

/* Clean up those related to VIA ACE and hand optimize aes_cbc_encrypt and aes_cbc_decrypt */
/* move the xmm registers save/restore originally inside the callee functions into these 2 caller functions */
/*
	That is, the updated *iv (16-bytes) is written back
	to the memory in the caller function pointed by the input argument.
	In the implementation, *iv is locally saved in %xmm7.
	Before return, we now write %xmm7 back to *iv.

	Note: we only do this in CommonCrypto. In the kernel, there are some other functions (IOKit/vm_pageout, e.g.)
	that might assume *iv is read only, and therefore should not be changed. This is being tracked in
	
*/


#if 0

aes_rval aes_ecb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_encrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1)) return 1;
    while(nb--) {
        aes_encrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
    return 0;
}

aes_rval aes_ecb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_decrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1)) return 1;
    while(nb--) {
        aes_decrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
    return 0;
}
#endif

#if 0
aes_rval vng_aes_encrypt_cbc(const unsigned char *ibuf, unsigned char *iv, unsigned int num_blk,
					 unsigned char *obuf, const aes_encrypt_ctx ctx[1])
{
		int i;
		
		while (num_blk--) {
			*iv ^= ibuf;			// 128-bit	
            aes_encrypt(*iv, *iv, ctx);
            memcpy(obuf, iv, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
			
		}		

		return 0;
}
#endif

	.text
	.p2align	4,0x90
	.globl _vng_aes_encrypt_opt_cbc
_vng_aes_encrypt_opt_cbc:

	// save registers and allocate stack memory for xmm registers and calling arguments (i386 only)
#if	defined	__i386__
	push	%ebp
	mov		%esp, %ebp
	push	%ebx					// to be used as ibuf
	push	%edi					// to be used as obuf
	sub		$(16+16+7*16), %esp		// 12 (calling arguments) + 4 (%esi) + 16 (iv) + 7*16 (xmm)
	mov		%esi, 12(%esp)			// save %esp in the unused 4-bytes, to be used as num_blk

	#define	sp	%esp
#else	// __x86_64__
	push	%rbp
	mov		%rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	sub		$(8+16+5*16+16), %rsp	// 8 (align) + 16 (dummy iv) + 5*16 (xmm) + 16 (for i386-x86_64 consistency)	

	#define	sp	%rsp
#endif

	// save xmm registers for kernel use
	// xmm6-xmm7 will be used locally
	// xmm0-xmm2 (x86_64) or xmm0-/xmm4 (i386) will be used inside _AccelerateCrypto_AES_encrypt_xmm_no_save (non-restored)
	// there is a hole not used for xmm, which is 48(sp). 
	// it has been used to store iv (16-bytes) in i386 code
	// for consistency between i386 and x86_64, this hole is dummied in x86_64 code
	// also the 1st 16 bytes (sp) is dummied in x86_64 code

	// the following code is changed per to a request from commoncrypto, it use directly *iv, not a local copy

#if CC_KERNEL
	movaps	%xmm7, 16(sp)
	movaps	%xmm6, 32(sp)
	movaps	%xmm0, 64(sp)
	movaps	%xmm1, 80(sp)
	movaps	%xmm2, 96(sp)
#if defined	__i386__
	movaps	%xmm3, 112(sp)
	movaps	%xmm4, 128(sp)
#endif
#endif

	// set up registers from calling arguments

#if defined	__i386__

	mov		12(%ebp), %eax			// iv
	mov		24(%ebp), %edx			// ctx
	movups	(%eax), %xmm7			// in_iv	
	mov		%eax, (%esp)			// 1st iv for aes_encrypt
	mov		%eax, 4(%esp)			// 2nd iv for aes_encrypt
	mov		%edx, 8(%esp)			// ctx for aes_encrypt
	mov		8(%ebp), %ebx			// ibuf
	mov		16(%ebp), %esi			// num_blk
	mov		20(%ebp), %edi			// obuf

	#define	ibuf	%ebx
	#define	obuf	%edi
	#define num_blk	%esi	

#else	//	__x86_64__, calling arguments order : rdi/rsi/rdx/rcx/r8

	mov		%rdi, %rbx				// ibuf
	mov		%rsi, %r12				// &iv
	movups	(%rsi), %xmm7			// in_iv
	mov		%rdx, %r13				// num_blk
	mov		%rcx, %r14				// obuf
	mov		%r8, %r15				// ctx	

	#define	ibuf	%rbx
	#define	iv		%r12
	#define	num_blk	%r13d
	#define	obuf	%r14	
	#define	ctx		%r15

#endif

	cmp		$1, num_blk				// num_blk vs 1
	jl		9f						// if num_blk < 1, branch to bypass the main loop
0:
	movups	(ibuf), %xmm6			// ibuf
#if defined	__i386__
	mov		12(%ebp), %eax			// &iv[0]
	pxor	%xmm6, %xmm7			// iv ^= ibuf
	movups	%xmm7, (%eax)			// save iv
#else
	pxor	%xmm6, %xmm7			// iv ^= ibuf
	movups	%xmm7, (iv)				// save iv
	mov		iv, %rdi				// 1st calling argument for aes_encrypt
	mov		iv, %rsi				// 2nd calling argument for aes_encrypt
	mov		ctx, %rdx				// 3rd calling argument for aes_encrypt
#endif
	call	_AccelerateCrypto_AES_encrypt_xmm_no_save	// aes_encrypt(iv, iv, ctx)
#if defined __i386__
	mov		12(%ebp), %eax			// &iv[0]
	movups	(%eax), %xmm7			// read iv
#else
	movups	(iv), %xmm7				// read iv
#endif
	movups	%xmm7, (obuf)			// memcpy(obuf, iv, AES_BLOCK_SIZE);
	add		$16, ibuf				// ibuf += AES_BLOCK_SIZE; 
	add		$16, obuf				// obuf += AES_BLOCK_SIZE;	
	sub		$1, num_blk				// num_blk --
	jg		0b						// if num_blk > 0, repeat the loop
9:	

L_crypt_cbc_done:

	// save the updated *iv
#if defined __i386__
	mov		12(%ebp), %eax
	movups	%xmm7, (%eax)
#else
	movups	%xmm7, (iv)
#endif

	// restore xmm registers due to kernel use
#if CC_KERNEL
	movaps	16(sp), %xmm7
	movaps	32(sp), %xmm6
	movaps	64(sp), %xmm0
	movaps	80(sp), %xmm1
	movaps	96(sp), %xmm2
#if defined	__i386__
	movaps	112(sp), %xmm3
	movaps	128(sp), %xmm4
#endif
#endif

	xor		%eax, %eax				// to return 0 for SUCCESS

#if	defined	__i386__
	mov		12(%esp), %esi			// restore %esi
	add		$(16+16+7*16), %esp		// 12 (calling arguments) + 4 (%esi) + 16 (iv) + 7*16 (xmm)
	pop		%edi
	pop		%ebx
#else
	add		$(8+16+5*16+16), %rsp	// 8 (align) + 16 (dummy iv) + 5*16 (xmm) + 16 (for i386-x86_64 consistency)	
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	pop		%rbx
#endif
	leave
	ret

#if 0
aes_rval vng_aes_decrypt_cbc(const unsigned char *ibuf, unsigned char *iv, unsigned int num_blk,
					 unsigned char *obuf, const aes_decrypt_ctx cx[1])
{
		unsigned char tmp[16];
		int i;
		
		while (num_blk--) {

            memcpy(tmp, ibuf, AES_BLOCK_SIZE);
            aes_decrypt(ibuf, obuf, ctx);
			obuf ^= *iv;
            memcpy(iv, tmp, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
		}

		return 0;
}
#endif

	.text
	.p2align	4,0x90
	.globl	_vng_aes_decrypt_opt_cbc
_vng_aes_decrypt_opt_cbc:
	// save registers and allocate stack memory for xmm registers and calling arguments (i386 only)
#if	defined	__i386__
	push	%ebp
	mov		%esp, %ebp
	push	%ebx					// to be used as ibuf
	push	%edi					// to be used as obuf
	sub		$(16+16+7*16), %esp		// 12 (calling arguments) + 4 (%esi) + 16 (iv) + 7*16 (xmm)
	mov		%esi, 12(%esp)			// save %esp in the unused 4-bytes, to be used as num_blk

	#define	sp	%esp
#else	// __x86_64__
	push	%rbp
	mov		%rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	sub		$(8+16+5*16+16), %rsp	// 8 (align) + 16 (dummy iv) + 5*16 (xmm) + 16 (for i386-x86_64 consistency)	

	#define	sp	%rsp
#endif

	// save xmm registers for kernel use
	// xmm6-xmm7 will be used locally
	// xmm0-xmm2 (x86_64) or xmm0-/xmm4 (i386) will be used inside _AccelerateCrypto_AES_decrypt_xmm_no_save (non-restored)
	// there is a hole not used for xmm, which is 48(sp). 
	// it has been used to store iv (16-bytes) in i386 code
	// for consistency between i386 and x86_64, this hole is dummied in x86_64 code
	// also the 1st 16 bytes (sp) is dummied in x86_64 code

#if CC_KERNEL
	movaps	%xmm7, 16(sp)
	movaps	%xmm6, 32(sp)
	movaps	%xmm0, 64(sp)
	movaps	%xmm1, 80(sp)
	movaps	%xmm2, 96(sp)
#if defined	__i386__
	movaps	%xmm3, 112(sp)
	movaps	%xmm4, 128(sp)
#endif
#endif

	// set up registers from calling arguments

#if defined	__i386__
	mov		12(%ebp), %eax			// &iv[0]
	mov		24(%ebp), %edx			// ctx
	movups	(%eax), %xmm7			// in_iv	
	mov		%edx, 8(%esp)			// ctx for aes_encrypt
	mov		8(%ebp), %ebx			// ibuf
	mov		16(%ebp), %esi			// num_blk
	mov		20(%ebp), %edi			// obuf

	#define	ibuf	%ebx
	#define	obuf	%edi
	#define num_blk	%esi	
#else	//	__x86_64__, rdi/rsi/rdx/rcx/r8
	mov		%rdi, %rbx				// ibuf
	mov		%rsi, %r12				// &iv[0]
	movups	(%rsi), %xmm7			// in_iv
	mov		%rdx, %r13				// num_blk
	mov		%rcx, %r14				// obuf 
	mov		%r8, %r15				// ctx	

	#define	ibuf	%rbx
	#define	num_blk	%r13d
	#define	obuf	%r14	
	#define	ctx		%r15

#endif
           // memcpy(tmp, ibuf, AES_BLOCK_SIZE);
           // aes_decrypt(ibuf, obuf, ctx);
			//	obuf ^= iv;
           // memcpy(iv, tmp, AES_BLOCK_SIZE);
           // ibuf += AES_BLOCK_SIZE;
           // obuf += AES_BLOCK_SIZE;

	cmp		$1, num_blk					// num_blk vs 1
	jl		L_crypt_cbc_done			// if num_blk < 1, bypass the main loop, jump to finishing code
0:
	movups	(ibuf), %xmm6				// tmp
#if defined	__i386__
	mov		ibuf, (sp)					// ibuf
	mov		obuf, 4(sp)					// obuf
#else
	mov		ibuf, %rdi					// ibuf 
	mov		obuf, %rsi					// obuf
	mov		ctx, %rdx					// ctx
#endif
	call	_AccelerateCrypto_AES_decrypt_xmm_no_save	// aes_decrypt(ibuf, obuf, ctx)
	movups	(obuf), %xmm0				// obuf
	pxor	%xmm7, %xmm0				// obuf ^= iv;
	movaps	%xmm6, %xmm7				// memcpy(iv, tmp, AES_BLOCK_SIZE);
	movups	%xmm0, (obuf)				// update obuf
	add		$16, ibuf					// ibuf += AES_BLOCK_SIZE; 
	add		$16, obuf					// obuf += AES_BLOCK_SIZE;	
	sub		$1, num_blk					// num_blk --
	jg		0b							// if num_blk > 0, repeat the loop
9:	

	// we are done here, the finishing code is identical to that in vng_aes_encrypt_cbc, so just jump to there
	jmp		L_crypt_cbc_done
#endif /* x86 based build */

