/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_FIELD_IMPL_H_
#define _SECP256K1_FIELD_IMPL_H_

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"

#if defined(USE_FIELD_10X26)
#include "field_10x26_impl.h"
#elif defined(USE_FIELD_5X52)
#include "field_5x52_impl.h"
#else
#error "Please select field implementation"
#endif

SECP256K1_INLINE static int cppethsecp256k1_fe_equal(const cppethsecp256k1_fe *a, const cppethsecp256k1_fe *b) {
    cppethsecp256k1_fe na;
    cppethsecp256k1_fe_negate(&na, a, 1);
    cppethsecp256k1_fe_add(&na, b);
    return cppethsecp256k1_fe_normalizes_to_zero(&na);
}

SECP256K1_INLINE static int cppethsecp256k1_fe_equal_var(const cppethsecp256k1_fe *a, const cppethsecp256k1_fe *b) {
    cppethsecp256k1_fe na;
    cppethsecp256k1_fe_negate(&na, a, 1);
    cppethsecp256k1_fe_add(&na, b);
    return cppethsecp256k1_fe_normalizes_to_zero_var(&na);
}

static int cppethsecp256k1_fe_sqrt(cppethsecp256k1_fe *r, const cppethsecp256k1_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    cppethsecp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    cppethsecp256k1_fe_sqr(&x2, a);
    cppethsecp256k1_fe_mul(&x2, &x2, a);

    cppethsecp256k1_fe_sqr(&x3, &x2);
    cppethsecp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x6, &x6);
    }
    cppethsecp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x9, &x9);
    }
    cppethsecp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        cppethsecp256k1_fe_sqr(&x11, &x11);
    }
    cppethsecp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        cppethsecp256k1_fe_sqr(&x22, &x22);
    }
    cppethsecp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        cppethsecp256k1_fe_sqr(&x44, &x44);
    }
    cppethsecp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        cppethsecp256k1_fe_sqr(&x88, &x88);
    }
    cppethsecp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        cppethsecp256k1_fe_sqr(&x176, &x176);
    }
    cppethsecp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        cppethsecp256k1_fe_sqr(&x220, &x220);
    }
    cppethsecp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x223, &x223);
    }
    cppethsecp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(&t1, &t1, &x2);
    cppethsecp256k1_fe_sqr(&t1, &t1);
    cppethsecp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    cppethsecp256k1_fe_sqr(&t1, r);
    return cppethsecp256k1_fe_equal(&t1, a);
}

static void cppethsecp256k1_fe_inv(cppethsecp256k1_fe *r, const cppethsecp256k1_fe *a) {
    cppethsecp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    cppethsecp256k1_fe_sqr(&x2, a);
    cppethsecp256k1_fe_mul(&x2, &x2, a);

    cppethsecp256k1_fe_sqr(&x3, &x2);
    cppethsecp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x6, &x6);
    }
    cppethsecp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x9, &x9);
    }
    cppethsecp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        cppethsecp256k1_fe_sqr(&x11, &x11);
    }
    cppethsecp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        cppethsecp256k1_fe_sqr(&x22, &x22);
    }
    cppethsecp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        cppethsecp256k1_fe_sqr(&x44, &x44);
    }
    cppethsecp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        cppethsecp256k1_fe_sqr(&x88, &x88);
    }
    cppethsecp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        cppethsecp256k1_fe_sqr(&x176, &x176);
    }
    cppethsecp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        cppethsecp256k1_fe_sqr(&x220, &x220);
    }
    cppethsecp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&x223, &x223);
    }
    cppethsecp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        cppethsecp256k1_fe_sqr(&t1, &t1);
    }
    cppethsecp256k1_fe_mul(r, a, &t1);
}

static void cppethsecp256k1_fe_inv_var(cppethsecp256k1_fe *r, const cppethsecp256k1_fe *a) {
#if defined(USE_FIELD_INV_BUILTIN)
    cppethsecp256k1_fe_inv(r, a);
#elif defined(USE_FIELD_INV_NUM)
    cppethsecp256k1_num n, m;
    static const cppethsecp256k1_fe negone = SECP256K1_FE_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2EUL
    );
    /* cppethsecp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };
    unsigned char b[32];
    int res;
    cppethsecp256k1_fe c = *a;
    cppethsecp256k1_fe_normalize_var(&c);
    cppethsecp256k1_fe_get_b32(b, &c);
    cppethsecp256k1_num_set_bin(&n, b, 32);
    cppethsecp256k1_num_set_bin(&m, prime, 32);
    cppethsecp256k1_num_mod_inverse(&n, &n, &m);
    cppethsecp256k1_num_get_bin(b, 32, &n);
    res = cppethsecp256k1_fe_set_b32(r, b);
    (void)res;
    VERIFY_CHECK(res);
    /* Verify the result is the (unique) valid inverse using non-GMP code. */
    cppethsecp256k1_fe_mul(&c, &c, r);
    cppethsecp256k1_fe_add(&c, &negone);
    CHECK(cppethsecp256k1_fe_normalizes_to_zero_var(&c));
#else
#error "Please select field inverse implementation"
#endif
}

static void cppethsecp256k1_fe_inv_all_var(cppethsecp256k1_fe *r, const cppethsecp256k1_fe *a, size_t len) {
    cppethsecp256k1_fe u;
    size_t i;
    if (len < 1) {
        return;
    }

    VERIFY_CHECK((r + len <= a) || (a + len <= r));

    r[0] = a[0];

    i = 0;
    while (++i < len) {
        cppethsecp256k1_fe_mul(&r[i], &r[i - 1], &a[i]);
    }

    cppethsecp256k1_fe_inv_var(&u, &r[--i]);

    while (i > 0) {
        size_t j = i--;
        cppethsecp256k1_fe_mul(&r[j], &r[i], &u);
        cppethsecp256k1_fe_mul(&u, &u, &a[j]);
    }

    r[0] = u;
}

static int cppethsecp256k1_fe_is_quad_var(const cppethsecp256k1_fe *a) {
#ifndef USE_NUM_NONE
    unsigned char b[32];
    cppethsecp256k1_num n;
    cppethsecp256k1_num m;
    /* cppethsecp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };

    cppethsecp256k1_fe c = *a;
    cppethsecp256k1_fe_normalize_var(&c);
    cppethsecp256k1_fe_get_b32(b, &c);
    cppethsecp256k1_num_set_bin(&n, b, 32);
    cppethsecp256k1_num_set_bin(&m, prime, 32);
    return cppethsecp256k1_num_jacobi(&n, &m) >= 0;
#else
    cppethsecp256k1_fe r;
    return cppethsecp256k1_fe_sqrt(&r, a);
#endif
}

#endif
