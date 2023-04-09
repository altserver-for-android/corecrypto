/* Copyright (c) (2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "crypto_test_ccn.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "ccn_op.h"
#include "ccn_internal.h"
#include "cc_memory.h"
#include <corecrypto/cc.h>
#include "cczp_internal.h"
#include "cc_workspaces.h"

static int test_ccn_sqr()
{
    ccnBuffer input = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    cc_size n = input->len;
    cc_unit square_result[n * 2];
    cc_unit mult_result[n * 2];

    CC_DECL_WORKSPACE_TEST(ws);
    ccn_sqr_ws(ws, n, square_result, input->units);
    ccn_mul_ws(ws, n, mult_result, input->units, input->units);
    CC_FREE_WORKSPACE(ws);

    ok_ccn_cmp(n, square_result, mult_result, "ccn_sqr_ws() failed");

    free(input);
    return 1;
}

static void mult(cc_unit *r, cc_size ns, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    cc_assert(r != s);
    cc_assert(r != t);

    r[ns] = ccn_mul1(ns, r, s, t[0]);
    while (nt > 1) {
        r += 1;
        t += 1;
        nt -= 1;
        r[ns] = ccn_addmul1(ns, r, s, t[0]);
    }
}

static int verify_ccn_div_euclid(cc_size nq,
                                 const cc_unit *q,
                                 cc_size nr,
                                 const cc_unit *r,
                                 cc_size na,
                                 const cc_unit *a,
                                 cc_size nd,
                                 const cc_unit *d)
{
    cc_unit v[nq + nd];
    // ccn_zero(nq+nd, v);
    mult(v, nq, q, nd, d);
    ccn_addn(nq + nd, v, v, nr, r);

    int rc = ccn_cmp(na, a, v);
    return rc;
}

#define CCN_READ_WRITE_TEST_N 3
#define CCN_READ_WRITE_TEST_BYTES ccn_sizeof_n(CCN_READ_WRITE_TEST_N)
static int test_ccn_write_test(size_t size) {
    int rc = 1;
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[size+1+CCN_UNIT_SIZE];
    uint8_t expected_t_bytes[size+2+CCN_UNIT_SIZE];
    
    
    size_t MSByte_index = sizeof(expected_t_bytes)-size-1;
    size_t LSByte_index = sizeof(expected_t_bytes)-2;
    
    // Set a big integer with the given size
    ccn_clear(CCN_READ_WRITE_TEST_N,t);
    cc_clear(sizeof(expected_t_bytes),expected_t_bytes);
    if (size>0) {
        ccn_set_bit(t, 0, 1);
        ccn_set_bit(t, size*8-1, 1);
        expected_t_bytes[LSByte_index]=0x01;
        expected_t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(t, 9, 1);
        expected_t_bytes[LSByte_index-1]|=0x02;
    }
    
    // Test ccn_write_uint, which supports truncation
    if(size>0) {
        ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes);
        rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size,t_bytes);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Extra output",size);
    
    // Test ccn_write_uint_padded, which supports truncation and padding
    if(size>0) {
        rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), 0, "Size %zu: return value",size);
        rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: Truncated output",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %d: Extra output",size);
    
    // Test ccn_write_uint_padded_ct, which supports padding, but not truncation
    if(size>0) {
        rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), CCERR_PARAMETER, "Size %zu: return value",size);
    }
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    return rc;
}

static int test_ccn_read_test(size_t size) {
    int rc = 1;
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit expected_t [CCN_READ_WRITE_TEST_N];
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[CCN_READ_WRITE_TEST_BYTES];
    
    // Set a big integer with the given size
    size_t MSByte_index = sizeof(t_bytes)-size;
    size_t LSByte_index = sizeof(t_bytes)-1;
    ccn_clear(CCN_READ_WRITE_TEST_N,expected_t);
    cc_clear(sizeof(t_bytes),t_bytes);
    if (size>0) {
        ccn_set_bit(expected_t, 0, 1);
        ccn_set_bit(expected_t, size*8-1, 1);
        t_bytes[LSByte_index]=0x01;
        t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(expected_t, 9, 1);
        t_bytes[LSByte_index-1]|=0x02;
    }

    rc&=is(ccn_read_uint(CCN_READ_WRITE_TEST_N,t,CCN_READ_WRITE_TEST_BYTES,t_bytes),0,"Size %zu: Return value",size);
    rc&=ok_ccn_cmp(CCN_READ_WRITE_TEST_N, t, expected_t, "Size %zu: Exact size",size);
    
    if (size>0) {
        rc&=is(ccn_read_uint(ccn_nof_size(size)-1,t,size,&t_bytes[MSByte_index]),CCERR_PARAMETER,"Size %zu: Overflow protection",size);
    }
    
    return rc;
}

#define num_of_tests_ccn_read_write 621 // Keep track of number of tests below so we can add to total testplan count
static int test_ccn_read_write() {
    int rc = 1;
    for (size_t i=0;i<=CCN_READ_WRITE_TEST_BYTES;i++) {
        rc&=test_ccn_read_test(i);
        rc&=test_ccn_write_test(i);
    }
    return rc;
}

static int test_ccn_div(size_t modulus_bits, size_t modulus_real_bits, size_t divisor_bits)
{
    struct ccrng_state *rng = global_test_rng;
    if (modulus_real_bits > modulus_bits)
        modulus_real_bits = modulus_bits;

    // create divisor
    cc_size nd = ccn_nof(modulus_bits);
    cc_unit d[nd];
    cc_unit r[nd];
    ccn_zero(nd, d);
    ccn_random_bits(modulus_real_bits, d, rng);

    // create random dividend
    cc_size na = ccn_nof(divisor_bits);
    cc_unit a[na];
    ccn_zero(na, a);
    cc_unit q[na];
    ccn_zero(na, q);
    ccn_random_bits(divisor_bits, a, rng);

    // other rc's are input parameter error and are considered fine here
    int rc = ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    ok(rc != -1, "ccn_div_euclid() returned error");
    if (rc == 0) {
        rc = verify_ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    } else
        rc = 0;

    return rc;
}

static void ccn_addn_kat()
{
    ccnBuffer s = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    ccnBuffer t = hexStringToCcn("00000000000000000000000000000001");
    cc_size n = s->len;
    cc_unit r[n];

    cc_unit cr = ccn_add(t->len, r, s->units, t->units);
    ok(cr == 1, "ccn_add carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_addn(n, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn KAT");
    ok(ccn_is_zero(n, r), "ccn_addn KAT");

    cr = ccn_addn(t->len, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_add1(0, r, r, 7);
    ok(cr == 7, "ccn_add1 carry KAT");

    cr = ccn_addn(n, r, s->units, n, s->units);
    ok(cr == 1, "ccn_addn carry KAT");

    free(s);
    free(t);
}

const struct rshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} rshift_test_vectors[] = {
#include "../test_vectors/shift_right.kat"
};

const size_t rshift_test_vectors_num = CC_ARRAY_LEN(rshift_test_vectors);

static int test_ccn_shift_right()
{
    for (unsigned i = 0; i < rshift_test_vectors_num; i++) {
        const struct rshift_test_vector *test = &rshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = x->len;
        cc_unit r2[n];

        ccn_shift_right_multi(n, r2, x->units, (size_t)k->units[0]);
        ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);

        if (k->units[0] < CCN_UNIT_BITS) {
            ccn_cond_shift_right(n, 1, r2, x->units, (size_t)k->units[0]);
            ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);
        } else {
            ok(true, "easier to calculate the test count that way");
        }

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

const struct lshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} lshift_test_vectors[] = {
#include "../test_vectors/shift_left.kat"
};

const size_t lshift_test_vectors_num = CC_ARRAY_LEN(lshift_test_vectors);

static int test_ccn_shift_left()
{
    for (unsigned i = 0; i < lshift_test_vectors_num; i++) {
        const struct lshift_test_vector *test = &lshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = r->len;
        cc_unit r2[n], x2[n];
        ccn_setn(n, x2, x->len, x->units);

        ccn_shift_left_multi(n, r2, x2, (size_t)k->units[0]);
        ok_ccn_cmp(n, r->units, r2, "r = x << %llu", k->units[0]);

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

static void test_ccn_sub1(void)
{
    cc_size n = 1;
    cc_unit r[n];
    cc_unit s[n];

    ccnBuffer t1 = hexStringToCcn("00000000000000000000000000000001");
    ccnBuffer t2 = hexStringToCcn("ffffffffffffffffffffffffffffffff");
    ccnBuffer t3 = hexStringToCcn("00000001000000000000000000000001");

    cc_unit borrow = ccn_sub1(0, r, s, 7);
    is(borrow, (cc_unit)7, "ccn_sub1 with zero length scalar failed");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(ccn_is_zero(t1->len, t1->units), "t1 should be 0");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 1, "ccn_sub1 should borrow");
    ok_ccn_cmp(t1->len, t1->units, t2->units, "t1 should be -1");

    borrow = ccn_sub1(t2->len, t2->units, t2->units, ~CC_UNIT_C(0));
    is(borrow, 0, "ccn_sub1 shouldn't borrow");

    borrow = ccn_sub1(t3->len, t3->units, t3->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(!ccn_is_zero(t3->len, t3->units), "t3 shouldn't be 0");

    borrow = ccn_subn(t3->len, t3->units, t3->units, t2->len, t2->units);
    is(borrow, 1, "ccn_subn should borrow");

    free(t1);
    free(t2);
    free(t3);
}

static int test_ccn_cmp_zerolen(void)
{
    int cmp;
    cc_size n = 0;
    cc_unit r[1];
    cc_unit s[1];

    cmp = ccn_cmp(n, r, s);
    is(cmp, 0, "ccn_cmp with size zero should return zero");

    return 1;
}

static void test_ccn_bitlen(void)
{
    cc_unit z[5] = {0, 0, 0, 0, 0};
    is(ccn_bitlen(5, z), 0, "ccn_bitlen() returned wrong result");
    is(ccn_bitlen(0, z), 0, "ccn_bitlen() returned wrong result");

    cc_unit a[5] = {0, 0, 1, 0, 0};
    is(ccn_bitlen(5, a), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit b[5] = {1, 0, 1, 0, 0};
    is(ccn_bitlen(5, b), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit c[5] = {1, 0, 1, 0, 1};
    is(ccn_bitlen(5, c), 4 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit d[5] = {1, 0, 0, 0, 0};
    is(ccn_bitlen(5, d), 1, "ccn_bitlen() returned wrong result");
}

static int test_ccn_abs(void)
{
    cc_unit a[1] = {5};
    cc_unit b[1] = {4};
    cc_unit r[1];

    CC_DECL_WORKSPACE_TEST(ws);

    is(ccn_abs_ws(ws, 1, r, a, b), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs_ws(ws, 1, r, a, a), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_zero(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs_ws(ws, 1, r, b, a), 1, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static void test_ccn_cmpn()
{
    cc_unit a[4] = { 1, 2, 0, 0 };
    cc_unit b[4] = { 1, 2, 0, 3 };

    // ns == nt
    is(ccn_cmpn(0, a, 0, b), 0, "{} == {}");
    is(ccn_cmpn(1, a, 1, b), 0, "{1} == {1}");
    is(ccn_cmpn(2, a, 2, b), 0, "{1,2} == {1,2}");
    is(ccn_cmpn(3, a, 3, b), 0, "{1,2,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 4, b), -1, "{1,2,0,0} < {1,2,0,3}");
    is(ccn_cmpn(4, b, 4, a), 1, "{1,2,0,3} > {1,2,0,0}");

    // ns > nt
    is(ccn_cmpn(4, a, 3, b), 0, "{1,2,0,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 2, b), 0, "{1,2,0,0} == {1,2}");
    is(ccn_cmpn(3, a, 2, b), 0, "{1,2,0} == {1,2}");
    is(ccn_cmpn(4, a, 1, b), 1, "{1,2,0,0} > {1}");
    is(ccn_cmpn(3, a, 1, b), 1, "{1,2,0} > {1}");
    is(ccn_cmpn(2, a, 1, b), 1, "{1,2} > {1}");
    is(ccn_cmpn(1, a, 0, b), 1, "{1} > {}");

    // ns < nt
    is(ccn_cmpn(3, b, 4, a), 0, "{1,2,0} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 4, a), 0, "{1,2} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 3, a), 0, "{1,2} == {1,2,0}");
    is(ccn_cmpn(1, b, 4, a), -1, "{1} < {1,2,0,0}");
    is(ccn_cmpn(1, b, 3, a), -1, "{1} < {1,2,0}");
    is(ccn_cmpn(1, b, 2, a), -1, "{1} < {1,2}");
    is(ccn_cmpn(0, b, 1, a), -1, "{} < {1}");
}

const struct gcd_test_vector {
    const char *gcd;
    const char *a;
    const char *b;
    const char *lcm;
} gcd_test_vectors[] = {
#include "../test_vectors/gcd_lcm.kat"
};

const size_t gcd_test_vectors_num = CC_ARRAY_LEN(gcd_test_vectors);

static int test_ccn_gcd()
{
    for (unsigned i = 0; i < gcd_test_vectors_num; i++) {
        const struct gcd_test_vector *test = &gcd_test_vectors[i];

        ccnBuffer gcd = hexStringToCcn(test->gcd);
        ccnBuffer a = hexStringToCcn(test->a);
        ccnBuffer b = hexStringToCcn(test->b);
        ccnBuffer lcm = hexStringToCcn(test->lcm);

        cc_size n = CC_MAX(a->len, b->len);
        cc_unit r[2 * n], an[n], bn[n];

        CC_DECL_WORKSPACE_TEST(ws);

        size_t k = ccn_gcd_ws(ws, n, r, a->len, a->units, b->len, b->units);
        ccn_shift_left_multi(n, r, r, k);
        ok_ccn_cmp(gcd->len, gcd->units, r, "r = gcd(a, b)");

        if (ccn_is_zero(n, r)) {
            ok(true, "hard to predict the test count otherwise");
        } else {
            ccn_setn(n, an, a->len, a->units);
            ccn_setn(n, bn, b->len, b->units);

            ccn_lcm_ws(ws, n, r, an, bn);
            ok_ccn_cmp(lcm->len, lcm->units, r, "r = lcm(a, b)");
        }

        CC_FREE_WORKSPACE(ws);

        free(gcd);
        free(a);
        free(b);
        free(lcm);
    }

    return 0;
}

static int test_ccn_div_exact()
{
    cc_size n = ccn_nof(256);
    cc_unit a[n * 2], b[n * 2], c[n * 2], r1[n * 2], r2[n * 2];
    ccn_clear(n * 2, a);
    ccn_clear(n * 2, b);

    CC_DECL_WORKSPACE_TEST(ws);

    for (size_t i = 0; i < 2000; i++) {
        ccn_random(n, a, global_test_rng);
        ccn_random(n, b, global_test_rng);
        ccn_mul(n, c, a, b);

        ccn_div_exact_ws(ws, n * 2, r1, c, b);
        is(ccn_div_ws(ws, n * 2, r2, n * 2, c, n * 2, b), CCERR_OK, "ccn_div_ws() succeeded");
        ok_ccn_cmp(n * 2, r1, r2, "quotients match");
    }

    // x / x == 1
    ccn_div_exact_ws(ws, n, a, a, a);
    ok(ccn_is_one(n * 2, a), "x / x == 1");

    // x / 1 == x
    ccn_div_exact_ws(ws, n, a, b, a);
    ok_ccn_cmp(n, a, b, "x / 1 == x");

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static int test_ccn_div_2n()
{
    cc_size n = 2;
    cc_unit q[n], r[n], a[n], d[n];

    ccn_seti(n, a, 0x51);
    ccn_seti(n, d, 0x10);

    int rv = ccn_div_euclid(n, q, n, r, n, a, n, d);
    is(rv, CCERR_OK, "ccn_div_euclid() failed");

    is(ccn_n(n, q), 1, "wrong quotient");
    is(q[0], 0x05, "wrong quotient");
    is(ccn_n(n, r), 1, "wrong remainder");
    is(r[0], 0x01, "wrong remainder");

    return 0;
}

const struct invmod_test_vector {
    const char *inv;
    const char *x;
    const char *m;
    int rv;
} invmod_test_vectors[] = {
#include "../test_vectors/invmod.kat"
};

const size_t invmod_test_vectors_num = CC_ARRAY_LEN(invmod_test_vectors);

static void test_ccn_invmod()
{
    for (unsigned i = 0; i < invmod_test_vectors_num; i++) {
        const struct invmod_test_vector *test = &invmod_test_vectors[i];

        ccnBuffer inv = hexStringToCcn(test->inv);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer m = hexStringToCcn(test->m);

        cc_size n = m->len;
        cc_unit r[n];

        CC_DECL_WORKSPACE_TEST(ws);

        int rv = ccn_invmod_ws(ws, n, r, x->len, x->units, m->units);
        is(rv, test->rv, "unexpected ccn_invmod_ws() result");
        ok_ccn_cmp(inv->len, inv->units, r, "r = ccn_invmod_ws(x, m)");

        // Test cczp_inv().
        if ((m->units[0] & 1) && ccn_cmpn(m->len, m->units, x->len, x->units) > 0) {
            cczp_decl_n(n, zp);
            CCZP_N(zp) = n;

            ccn_set(n, CCZP_PRIME(zp), m->units);
            is(cczp_init_ws(ws, zp), CCERR_OK, "cczp_init() failed");

            cc_unit xn[n];
            ccn_setn(n, xn, x->len, x->units);

            int rv = cczp_inv_ws(ws, zp, r, xn);
            is(rv, test->rv, "unexpected cczp_inv() result");
            ok_ccn_cmp(inv->len, inv->units, r, "r = cczp_inv(x, m)");
        } else {
            ok(true, "always increase test count");
            ok(true, "always increase test count");
            ok(true, "always increase test count");
        }

        CC_FREE_WORKSPACE(ws);

        free(inv);
        free(x);
        free(m);
    }
}

static const cc_unit expected_recips[] = {
    0x0,   0x4,   0x8,   0x5,   0x10,  0xc,   0xa,   0x9,   0x20,  0x1c,  0x19,  0x17,  0x15,  0x13,  0x12,  0x11,  0x40,  0x3c,
    0x38,  0x35,  0x33,  0x30,  0x2e,  0x2c,  0x2a,  0x28,  0x27,  0x25,  0x24,  0x23,  0x22,  0x21,  0x80,  0x7c,  0x78,  0x75,
    0x71,  0x6e,  0x6b,  0x69,  0x66,  0x63,  0x61,  0x5f,  0x5d,  0x5b,  0x59,  0x57,  0x55,  0x53,  0x51,  0x50,  0x4e,  0x4d,
    0x4b,  0x4a,  0x49,  0x47,  0x46,  0x45,  0x44,  0x43,  0x42,  0x41,  0x100, 0xfc,  0xf8,  0xf4,  0xf0,  0xed,  0xea,  0xe6,
    0xe3,  0xe0,  0xdd,  0xda,  0xd7,  0xd4,  0xd2,  0xcf,  0xcc,  0xca,  0xc7,  0xc5,  0xc3,  0xc0,  0xbe,  0xbc,  0xba,  0xb8,
    0xb6,  0xb4,  0xb2,  0xb0,  0xae,  0xac,  0xaa,  0xa8,  0xa7,  0xa5,  0xa3,  0xa2,  0xa0,  0x9f,  0x9d,  0x9c,  0x9a,  0x99,
    0x97,  0x96,  0x94,  0x93,  0x92,  0x90,  0x8f,  0x8e,  0x8d,  0x8c,  0x8a,  0x89,  0x88,  0x87,  0x86,  0x85,  0x84,  0x83,
    0x82,  0x81,  0x200, 0x1fc, 0x1f8, 0x1f4, 0x1f0, 0x1ec, 0x1e9, 0x1e5, 0x1e1, 0x1de, 0x1da, 0x1d7, 0x1d4, 0x1d0, 0x1cd, 0x1ca,
    0x1c7, 0x1c3, 0x1c0, 0x1bd, 0x1ba, 0x1b7, 0x1b4, 0x1b2, 0x1af, 0x1ac, 0x1a9, 0x1a6, 0x1a4, 0x1a1, 0x19e, 0x19c, 0x199, 0x197,
    0x194, 0x192, 0x18f, 0x18d, 0x18a, 0x188, 0x186, 0x183, 0x181, 0x17f, 0x17d, 0x17a, 0x178, 0x176, 0x174, 0x172, 0x170, 0x16e,
    0x16c, 0x16a, 0x168, 0x166, 0x164, 0x162, 0x160, 0x15e, 0x15c, 0x15a, 0x158, 0x157, 0x155, 0x153, 0x151, 0x150, 0x14e, 0x14c,
    0x14a, 0x149, 0x147, 0x146, 0x144, 0x142, 0x141, 0x13f, 0x13e, 0x13c, 0x13b, 0x139, 0x138, 0x136, 0x135, 0x133, 0x132, 0x130,
    0x12f, 0x12e, 0x12c, 0x12b, 0x129, 0x128, 0x127, 0x125, 0x124, 0x123, 0x121, 0x120, 0x11f, 0x11e, 0x11c, 0x11b, 0x11a, 0x119,
    0x118, 0x116, 0x115, 0x114, 0x113, 0x112, 0x111, 0x10f, 0x10e, 0x10d, 0x10c, 0x10b, 0x10a, 0x109, 0x108, 0x107, 0x106, 0x105,
    0x104, 0x103, 0x102, 0x101, 0x400, 0x3fc, 0x3f8, 0x3f4, 0x3f0, 0x3ec, 0x3e8, 0x3e4, 0x3e0, 0x3dd, 0x3d9, 0x3d5, 0x3d2, 0x3ce,
    0x3ca, 0x3c7, 0x3c3, 0x3c0, 0x3bc, 0x3b9, 0x3b5, 0x3b2, 0x3ae, 0x3ab, 0x3a8, 0x3a4, 0x3a1, 0x39e, 0x39b, 0x397, 0x394, 0x391,
    0x38e, 0x38b, 0x387, 0x384, 0x381, 0x37e, 0x37b, 0x378, 0x375, 0x372, 0x36f, 0x36c, 0x369, 0x366, 0x364, 0x361, 0x35e, 0x35b,
    0x358, 0x355, 0x353, 0x350, 0x34d, 0x34a, 0x348, 0x345, 0x342, 0x340, 0x33d, 0x33a, 0x338, 0x335, 0x333, 0x330, 0x32e, 0x32b,
    0x329, 0x326, 0x324, 0x321, 0x31f, 0x31c, 0x31a, 0x317, 0x315, 0x313, 0x310, 0x30e, 0x30c, 0x309, 0x307, 0x305, 0x303, 0x300,
    0x2fe, 0x2fc, 0x2fa, 0x2f7, 0x2f5, 0x2f3, 0x2f1, 0x2ef, 0x2ec, 0x2ea, 0x2e8, 0x2e6, 0x2e4, 0x2e2, 0x2e0, 0x2de, 0x2dc, 0x2da,
    0x2d8, 0x2d6, 0x2d4, 0x2d2, 0x2d0, 0x2ce, 0x2cc, 0x2ca, 0x2c8, 0x2c6, 0x2c4, 0x2c2, 0x2c0, 0x2be, 0x2bc, 0x2bb, 0x2b9, 0x2b7,
    0x2b5, 0x2b3, 0x2b1, 0x2b0, 0x2ae, 0x2ac, 0x2aa, 0x2a8, 0x2a7, 0x2a5, 0x2a3, 0x2a1, 0x2a0, 0x29e, 0x29c, 0x29b, 0x299, 0x297,
    0x295, 0x294, 0x292, 0x291, 0x28f, 0x28d, 0x28c, 0x28a, 0x288, 0x287, 0x285, 0x284, 0x282, 0x280, 0x27f, 0x27d, 0x27c, 0x27a,
    0x279, 0x277, 0x276, 0x274, 0x273, 0x271, 0x270, 0x26e, 0x26d, 0x26b, 0x26a, 0x268, 0x267, 0x265, 0x264, 0x263, 0x261, 0x260,
    0x25e, 0x25d, 0x25c, 0x25a, 0x259, 0x257, 0x256, 0x255, 0x253, 0x252, 0x251, 0x24f, 0x24e, 0x24d, 0x24b, 0x24a, 0x249, 0x247,
    0x246, 0x245, 0x243, 0x242, 0x241, 0x240, 0x23e, 0x23d, 0x23c, 0x23b, 0x239, 0x238, 0x237, 0x236, 0x234, 0x233, 0x232, 0x231,
    0x230, 0x22e, 0x22d, 0x22c, 0x22b, 0x22a, 0x229, 0x227, 0x226, 0x225, 0x224, 0x223, 0x222, 0x220, 0x21f, 0x21e, 0x21d, 0x21c,
    0x21b, 0x21a, 0x219, 0x218, 0x216, 0x215, 0x214, 0x213, 0x212, 0x211, 0x210, 0x20f, 0x20e, 0x20d, 0x20c, 0x20b, 0x20a, 0x209,
    0x208, 0x207, 0x206, 0x205, 0x204, 0x203, 0x202, 0x201,
};

static void test_ccn_make_recip()
{
    CC_DECL_WORKSPACE_TEST(ws);
    cc_unit recip[2];

    for (cc_unit i = 0; i < CC_ARRAY_LEN(expected_recips); i++) {
        ccn_make_recip_ws(ws, 1, recip, &i);
        ok_ccn_cmp(1, recip, &expected_recips[i], "wrong recip");
    }

    // Extend test with a consistency check instead of known reciprocal.
    for (cc_unit i = CC_ARRAY_LEN(expected_recips) | 1; i < (1ULL << 24); i++) {
        ccn_make_recip_ws(ws, 1, recip, &i);

        // Verify that (2^2b - recip * i) < i.
        cc_unit t1[2], t2[2];
        ccn_mul(1, t1, recip, &i); // t1 := recip * i

        ccn_clear(2, t2);
        ccn_set_bit(t2, 2 * ccn_bitlen(1, &i), 1); // t2 := 2^(2b)

        cc_unit c = ccn_sub(2, t1, t2, t1); // 2^(2b) - recip * i
        is(c, 0, "no borrow expected");
        ok(ccn_cmp(2, t1, &i) <= 0, "wrong recip");
    }

    // Explicitly check the reciprocal for a power of two.
    cc_size n = 2;
    cc_unit rem[n], d[n], r[n + 1], a[2 * n];
    ccn_seti(2 * n, a, 0x51);

    ccn_seti(n, d, 0x10); // 2^4
    ccn_make_recip_ws(ws, n, r, d);

    is(ccn_div_use_recip_ws(ws, 0, NULL, n, rem, 2 * n, a, n, d, r), CCERR_OK, "ccn_div_use_recip() failed");
    is(ccn_n(n, rem), 1, "wrong remainder");
    is(rem[0], 0x01, "wrong remainder");

    CC_FREE_WORKSPACE(ws);
}

#define MODULUS_BITS 653
#define MODULUS_REAL_BITS 457
#define DIVISOR_BITS 1985
int ccn_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int rc = 0;
    size_t modulus_bits = MODULUS_BITS;
    size_t modulus_real_bits = MODULUS_REAL_BITS;
    size_t divisor_bits = DIVISOR_BITS;

    int num_tests = 100334 + num_of_tests_ccn_read_write;
    num_tests += 20;                                // ccn_cmpn
    num_tests += 4002;                              // ccn_div_exact
    num_tests += 5;                                 // ccn_div_2n
    num_tests += gcd_test_vectors_num * 2;          // ccn_gcd
    num_tests += rshift_test_vectors_num * 2;       // ccn_shift_right
    num_tests += lshift_test_vectors_num;           // ccn_shift_left
    num_tests += invmod_test_vectors_num * 5;       // ccn_invmod
    num_tests += 3 + CC_ARRAY_LEN(expected_recips); // ccn_make_recip
    num_tests += ((1ULL << 24) - (CC_ARRAY_LEN(expected_recips) | 1)) * 2;
    plan_tests(num_tests);

    // Functional tests
    for (int i = 0; i < 25000; i++) {
        modulus_bits = cc_rand_unit() % 753 + 30;
        modulus_real_bits = modulus_bits / (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 5;

        divisor_bits = modulus_bits * (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 7;
        rc = test_ccn_div(modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");

        divisor_bits = modulus_bits / (cc_rand_unit() % 3 + 1) + cc_rand_unit() % 7;
        rc = test_ccn_div(modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");
    }

    // Negative tests
    cc_unit d[2] = { 0, 0 };
    cc_unit a[5] = { 5, 4, 3, 2, 1 };
    cc_unit q[5], r[2];

    rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
    is(rc, -2, "ccn_div_euclid() division by zero");
    for (int i = 50; i >= 1; i--) {
        d[0] = (cc_unit)i;
        rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc, 0, "ccn_div_euclid()");
        rc = verify_ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc, 0, "ccn_div_euclid() division by small divisor");
    }

    // Make sure arithmetic right shift is in place
    for (int i = 0; i < 200; i++) {
        cc_unit v = cc_rand_unit();
        ok(ccop_msb(v) == (ccn_bit(&v, CCN_UNIT_BITS - 1) ? ~(cc_unit)0 : 0), "ccop_msb() produces incorrect result");
    }

    ccn_addn_kat();
    test_ccn_sub1();
    test_ccn_shift_right();
    test_ccn_shift_left();
    is(test_ccn_sqr(), 1, "test_ccn_sqr failed");
    is(test_ccn_cmp_zerolen(), 1, "test_ccn_cmp_zerolen failed");
    is(test_ccn_read_write(),1, "test_ccn_read_write failed");
    test_ccn_bitlen();
    test_ccn_abs();
    test_ccn_cmpn();
    test_ccn_gcd();
    test_ccn_div_exact();
    test_ccn_div_2n();
    test_ccn_invmod();
    test_ccn_make_recip();

    return rc;
}
