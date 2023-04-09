/* Copyright (c) (2017-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCZP_INTERNAL_H_
#define _CORECRYPTO_CCZP_INTERNAL_H_

#include <stdbool.h>
#include <corecrypto/cczp.h>
#include "cc_internal.h"
#include "ccn_internal.h"
#include "cc_memory.h"

// cczp_hd must be defined separately without variable length array ccn[],
// because it is used in sructures such as ccdh_gp_decl_n
struct cczp_hd {
    __CCZP_HEADER_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

#define cczp_payload_nof_n(_n_) (1 + 2 * (_n_))
#define cczp_payload_sizeof_n(_n_) ccn_sizeof_n(cczp_payload_nof_n(_n_))

/* Return number of units that a struct cczp needs to be in units for a prime
   size of N units.  This is large enough for all operations.  */
#define cczp_nof_n(_n_) (ccn_nof_size(sizeof(struct cczp)) + cczp_payload_nof_n(_n_))
#define cczp_sizeof_n(_n_) ccn_sizeof_n(cczp_nof_n(_n_))

/* Return number of units that a struct cczp needs to be in units for a prime
   size of _n_ units. */
#define cczp_decl_n(_n_, _name_) cc_ctx_decl_vla(struct cczp, cczp_sizeof_n(_n_), _name_)
#define cczp_clear_n(_n_, _name_) cc_clear(cczp_sizeof_n(_n_), _name_)

/*
 * Struct type with function pointers for overridable cczp functions.
 */
struct cczp_funcs {
    // Modular multiplication.
    void (*CC_SPTR(cczp_funcs, mul))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
    // Modular squaring.
    void (*CC_SPTR(cczp_funcs, sqr))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Modular reduction.
    void (*CC_SPTR(cczp_funcs, mod))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Modular inversion.
    int (*CC_SPTR(cczp_funcs, inv))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Modular square root.
    int (*CC_SPTR(cczp_funcs, sqrt))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Conversion to a representation (e.g. into Montgomery space).
    void (*CC_SPTR(cczp_funcs, to))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Conversion from a representation (e.g. out of Montgomery space).
    void (*CC_SPTR(cczp_funcs, from))(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
    // Check whether "x" is the identity element.
    bool (*CC_SPTR(cczp_funcs, is_one))(cc_ws_t ws, cczp_const_t zp, const cc_unit *x);
};

/*
 * Default implementations for overridable cczp functions.
 *
 * You probably don't want to call these directly.
 */
void cczp_mul_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);
void cczp_sqr_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
void cczp_mod_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
int cczp_inv_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
int cczp_sqrt_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
void cczp_to_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
void cczp_from_default_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);
bool cczp_is_one_default_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *x);

/*
 * Struct holding pointers to all default implementations.
 */
#define CCZP_FUNCS_DEFAULT &cczp_default_funcs
extern const struct cczp_funcs cczp_default_funcs;

#define cczp_funcs_decl(_name_, _mul_, _sqr_, _mod_, _inv_, _sqrt_, _to_, _from_, _is_one_) \
    const struct cczp_funcs _name_ = {                                                      \
        .mul = _mul_,                                                                       \
        .sqr = _sqr_,                                                                       \
        .mod = _mod_,                                                                       \
        .inv = _inv_,                                                                       \
        .sqrt = _sqrt_,                                                                     \
        .to = _to_,                                                                         \
        .from = _from_,                                                                     \
        .is_one = _is_one_,                                                                 \
    }

#define cczp_funcs_decl_mod_inv(_name_, _mod_, _inv_) \
    cczp_funcs_decl(_name_,                           \
                    cczp_mul_default_ws,              \
                    cczp_sqr_default_ws,              \
                    _mod_,                            \
                    _inv_,                            \
                    cczp_sqrt_default_ws,             \
                    cczp_to_default_ws,               \
                    cczp_from_default_ws,             \
                    cczp_is_one_default_ws)

#define cczp_funcs_decl_inv(_name_, _inv_) \
    cczp_funcs_decl_mod_inv(_name_, cczp_mod_default_ws, _inv_)

#define cczp_funcs_decl_mod(_name_, _mod_) \
    cczp_funcs_decl_mod_inv(_name_, _mod_, cczp_inv_default_ws)

/*
 * Montgomery multiplication.
 */

// Additional to the cczp struct we cache:
//  * the negated inverse of the first word of the prime
//  * R (mod p)
//  * R^2 (mod p)
#define cczp_mm_nof_n(_n_) (ccn_nof_size(sizeof(struct cczp)) + 1 + 3 * (_n_))

#define cczp_mm_decl_n(_n_, _name_) cc_ctx_decl_vla(struct cczp, ccn_sizeof_n(cczp_mm_nof_n(_n_)), _name_)
#define cczp_mm_clear_n(_n_, _name_) cc_clear(ccn_sizeof_n(cczp_mm_nof_n(_n_)), _name_)

#define cczp_mm_p0inv(_zp_) *(CCZP_PRIME(_zp_) + (_zp_)->n)
#define cczp_mm_r1(_zp_) (CCZP_PRIME(_zp_) + (_zp_)->n + 1)
#define cczp_mm_r2(_zp_) (CCZP_PRIME(_zp_) + 2 * (_zp_)->n + 1)

/* Internal accessors and helpers. */

#define CCZP_RECIP(ZP) ((ZP)->ccn + CCZP_N(ZP))
#define CCZP_FUNCS(ZP) ((ZP)->funcs)

#define CCZP_FUNC_MUL(ZP) ((ZP)->funcs->mul)
#define CCZP_FUNC_SQR(ZP) ((ZP)->funcs->sqr)
#define CCZP_FUNC_MOD(ZP) ((ZP)->funcs->mod)
#define CCZP_FUNC_INV(ZP) ((ZP)->funcs->inv)
#define CCZP_FUNC_SQRT(ZP) ((ZP)->funcs->sqrt)
#define CCZP_FUNC_TO(ZP) ((ZP)->funcs->to)
#define CCZP_FUNC_FROM(ZP) ((ZP)->funcs->from)
#define CCZP_FUNC_IS_ONE(ZP) ((ZP)->funcs->is_one)

#define CCZP_FUNC_MUL_DEFAULT (CCZP_FUNCS_DEFAULT)->mul
#define CCZP_FUNC_SQR_DEFAULT (CCZP_FUNCS_DEFAULT)->sqr

/* Ensure both cczp_mod_prime(zp) and cczp_recip(zp) are valid. cczp_n and
   cczp_prime must have been previously initialized. The reciprocal will
   be computed and set. */
CC_NONNULL_ALL int cczp_init(cczp_t zp);

/* Return a pointer to the Reciprocal or Montgomery constant of zp, which is
 allocated cczp_n(zp) + 1 units long. */
CC_NONNULL((1)) CC_INLINE const cc_unit *cczp_recip(cczp_const_t zp)
{
    return zp->ccn + zp->n;
}

/*
 * Same as cczp_init with workspace
 */
CC_NONNULL_ALL
int cczp_init_ws(cc_ws_t ws, cczp_t zp);

/* Compute r = x + y mod cczp_prime(zp). Will write cczp_n(zp) units to r and
   reads cczp_n(zp) units units from x and y. If r and x are not identical
   they must not overlap. Only cczp_n(zp) and cczp_prime(zp) need to be valid. */
CC_NONNULL_ALL
int cczp_add(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

CC_NONNULL_ALL
void cczp_add_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/* Compute r = x - y mod cczp_prime(zp). Will write cczp_n(zp) units to r and
   reads cczp_n(zp) units units from x and y. If r and x are not identical
   they must not overlap. Only cczp_n(zp) and cczp_prime(zp) need to be valid. */
CC_NONNULL_ALL
int cczp_sub(cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

CC_NONNULL_ALL
void cczp_sub_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

/* Compute r = x / 2 mod cczp_prime(zp). Will write cczp_n(zp) units to r and
   reads cczp_n(zp) units units from x. If r and x are not identical
   they must not overlap. Only cczp_n(zp) and cczp_prime(zp) need to be valid. */
CC_NONNULL_ALL
void cczp_div2_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/* Compute r = s2n mod cczp_prime(zp). Will write cczp_n(zp)
 units to r and reads 2 * cczp_n(zp) units units from s2n. If r and s2n are not
 identical they must not overlap.  Before calling this function cczp_init(zp)
 must have been called. */
CC_NONNULL_ALL
void cczp_mod_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s2n);

/* Compute r = sn mod cczp_prime(zp), Will write cczp_n(zp)
 units to r and reads sn units units from s. If r and s are not
 identical they must not overlap.  Before calling this function
 cczp_init(zp) must have been called. */
CC_NONNULL_ALL
int cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s);

/*
 * Same as cczp_modn with workspace
 */
CC_NONNULL_ALL
int cczp_modn_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s);

/* Compute r = x * y mod cczp_prime(zp). Will write cczp_n(zp) units to r
   and reads cczp_n(zp) units units from both x and y. If r and x are not
   identical they must not overlap, The same holds for r and y.  Before
   calling this function cczp_init(zp) must have been called. */
CC_NONNULL_ALL
int cczp_mul(cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y);

/*
 * Same as cczp_mul_ws with workspace
 */
CC_NONNULL_ALL
void cczp_mul_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y);

/* Compute r = m ^ e (mod p), where p=cczp_prime(zp). Writes n=cczp_n(zp) units to r and
 reads n units units from m and e. If r and m are not identical
 they must not overlap. r and e must not overlap nor be identical.
 Before calling this function cczp_init(zp) must have been called.

 Use this function with PUBLIC values only, it may leak the parameters
 in timing / Simple power analysis
 */
CC_NONNULL_ALL
int cczp_power_fast(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e);

/*
 * Same as cczp_power_fast() with workspace
 */
CC_NONNULL_ALL
int cczp_power_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e);

/* Compute r = x * x mod cczp_prime(zp). Will write cczp_n(zp) units to r
   and reads cczp_n(zp) units from x. If r and x are not identical they must
   not overlap. Before calling this function cczp_init(zp) must have
   been called. */
CC_NONNULL_ALL
int cczp_sqr(cczp_const_t zp, cc_unit *r, const cc_unit *x);

CC_NONNULL_ALL
void cczp_sqr_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

#define cczp_sqr_times_ws(_ws_, _zp_, _r_, _x_, _n_) \
    ccn_set(cczp_n(zp), _r_, _x_);                   \
    for (unsigned i = 0; i < _n_; i++) {             \
        cczp_sqr_ws(_ws_, _zp_, _r_, _r_);           \
    }

/*! @function cczp_sqrt
 @abstract Computes the square root r for r^2 = x mod p.

 @discussion DO NOT use when p is secret.

 @param zp Multiplicative group Z/(p).
 @param r  Square root of x
 @param x  Quadratic residue

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_sqrt(cczp_const_t zp, cc_unit *r, const cc_unit *x);

CC_NONNULL_ALL
int cczp_sqrt_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function cczp_sqrt_tonelli_shanks_precomp_ws
 @abstract Computes x^(1/2) (mod p) via constant-time Tonelli-Shanks, given
           precomputed constants for faster computation.

 @discussion This follows the constant-time algorithm described by the CFRG's
             "Hashing to Elliptic Curves" document. It also further explains
             the precomputed constants c1,c3,c5.

 @param ws Workspace
 @param zp Multiplicative group Z/(p)
 @param r  Square root of x
 @param x  Quadratic residue
 @param c1 Largest integer such that 2^c1 divides p - 1
 @param c3 Equal to (c2 - 1) / 2, where c2 = (p - 1) / (2^c1).
 @param c5 Equal to c4^c2 (mod p) where c4 is a non-residue in Z/(p).

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_sqrt_tonelli_shanks_precomp_ws(cc_ws_t ws,
                                        cczp_const_t zp,
                                        cc_unit *r,
                                        const cc_unit *x,
                                        size_t c1,
                                        const cc_unit *c3,
                                        const cc_unit *c5);

/*! @function cczp_is_quadratic_residue_ws
 @abstract Computes the Legendre symbol (a/p) to determine whether a is a
 quadratic residue mod p.

 @param ws Workspace
 @param zp Multiplicative group Z/(p)
 @param a  Number to check

 @return 1 if a is a quadratic residue.
 0 if a is a non-residue.
 An error code if gcd(a,p) > 1.
 */
CC_NONNULL_ALL
int cczp_is_quadratic_residue_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *a);

/*! @function cczp_power_ws
 @abstract Computes r := s^e, where s < p is required.

 @param ws Workspace
 @param zp Multiplicative group Z/(p).
 @param r  Result r = s^e (mod p).
 @param s  Base s, raised to the power of e.
 @param ebitlen Bit length of e (required to hide variable bit lengths).
 @param e  Exponent e.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_power_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, size_t ebitlen, const cc_unit *e);

/*! @function cczp_power_blinded_ws
 @abstract Computes r := s^e, where s < p is required.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p).
 @param r   Result r = s^e (mod p).
 @param s   Base s, raised to the power of e.
 @param e   Exponent e.
 @param rng RNG for blinding.

 @discussion This function blinds only the exponent.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_power_blinded_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e, struct ccrng_state *rng);

/*! @function cczp_inv
 @abstract Computes the modular inverse of x (mod p), r = x^-1 (mod p), for
           any 0 < x < p with p odd, via constant-time, binary XGCD.

 @param zp Multiplicative group Z/(p).
 @param r  Resulting modular inverse.
 @param x  Element to invert.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *x);

int cczp_inv_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*
 * Montgomery representation support
 */

/*! @function cczp_to_ws
 @abstract Converts an affine coordinate to another representation.

 @param ws  Workspace of size CCZP_TO_WORKSPACE_N(cczp_n(zp))
 @param zp  Multiplicative group Z/(p).
 @param r   Output coordinate.
 @param x   Input affine coordinate.
 */
CC_NONNULL_ALL
void cczp_to_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

CC_NONNULL_ALL
int cczp_to(cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function cczp_from_ws
 @abstract Converts a coordinate to its affine representation.

 @param ws  Workspace of size CCZP_FROM_WORKSPACE_N(cczp_n(zp))
 @param zp  Multiplicative group Z/(p).
 @param r   Output affine coordinate.
 @param x   Input coordinate.
 */
CC_NONNULL_ALL
void cczp_from_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

CC_NONNULL_ALL
int cczp_from(cczp_const_t zp, cc_unit *r, const cc_unit *x);

#define cczp_const_decl(zp, ini) cczp_const_t(zp) = (ini);

/*! @function cczp_generate_non_zero_element
 @abstract Generate an element within GF(p) (i.e. 0 < r < p)

 @param zp  Multiplicative group Z/(p)
 @param rng RNG state
 @param r   Output random element

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_generate_non_zero_element(cczp_const_t zp, struct ccrng_state *rng, cc_unit *r);

CC_NONNULL_ALL
int cczp_generate_non_zero_element_ws(cc_ws_t ws, cczp_const_t zp, struct ccrng_state *rng, cc_unit *r);

/*! @function cczp_generate_random_element_ws
 @abstract Generate an element within GF(p) (i.e. 0 <= r < p)

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param rng RNG state
 @param out Output random element

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_generate_random_element_ws(cc_ws_t ws, cczp_const_t zp, struct ccrng_state *rng, cc_unit *out);

/*! @function cczp_is_one_ws
 @abstract Returns whether a given group element is the identity element.

 @discussion This works for numbers in Montgomery space as well.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param x   Group element to check

 @return true for the identity element, false otherwise
 */
CC_NONNULL_ALL
bool cczp_is_one_ws(cc_ws_t ws, cczp_const_t zp, const cc_unit *x);

/*! @function cczp_mm_init_ws
 @abstract Initialize a cczp struct for Montgomery modular multiplication.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param n   Size of p
 @param p   Prime p

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_mm_init_ws(cc_ws_t ws, cczp_t zp, cc_size n, const cc_unit *p);

/*! @function cczp_mm_power_fast_ws
 @abstract Run cczp_power_fast() with Montgomery multiplication.
           Computes r := x^e, where x < p is required.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the exponentiation
 @param x   Base
 @param e   Exponent

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_mm_power_fast_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, const cc_unit *e);

/*! @function cczp_mm_power_ws
 @abstract Run cczp_power_ws() with Montgomery multiplication.
           Computes r := x^e, where x < p is required.

 @param ws  Workspace
 @param zp  Multiplicative group Z/(p)
 @param r   Result of the exponentiation
 @param x   Base
 @param ebitlen Bit length of e (required to hide variable bit lengths).
 @param e   Exponent

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL_ALL
int cczp_mm_power_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x, size_t ebitlen, const cc_unit *e);

/*!
 @function cczp_negate
 Replace source with its negation mod p, where p is given in the field.
 @param zp  The ring in which we want source's negation to be computed
 @param r result of the negation
 @param x The value to negate
 @discussion r, and x can be the same, but otherwise should not overlap
 */
CC_NONNULL_ALL
void cczp_negate(cczp_const_t zp, cc_unit *r, const cc_unit *x);

/*! @function cczp_inv_field_ws
 @abstract Computes the modular inverse of x (mod p), r = x^-1 (mod p), for
           any 0 < x < p with p prime, as r = x^(p-2) (mod p).

 @param ws Workspace
 @param zp Multiplicative group Z/(p).
 @param r  Resulting modular inverse.
 @param x  Element to invert.

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
int cczp_inv_field_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *x);

#endif // _CORECRYPTO_CCZP_INTERNAL_H_
