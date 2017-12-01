/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_NUM_
#define _SECP256K1_NUM_

#ifndef USE_NUM_NONE

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(USE_NUM_GMP)
#include "num_gmp.h"
#else
#error "Please select num implementation"
#endif

/** Copy a number. */
static void cppethsecp256k1_num_copy(cppethsecp256k1_num *r, const cppethsecp256k1_num *a);

/** Convert a number's absolute value to a binary big-endian string.
 *  There must be enough place. */
static void cppethsecp256k1_num_get_bin(unsigned char *r, unsigned int rlen, const cppethsecp256k1_num *a);

/** Set a number to the value of a binary big-endian string. */
static void cppethsecp256k1_num_set_bin(cppethsecp256k1_num *r, const unsigned char *a, unsigned int alen);

/** Compute a modular inverse. The input must be less than the modulus. */
static void cppethsecp256k1_num_mod_inverse(cppethsecp256k1_num *r, const cppethsecp256k1_num *a, const cppethsecp256k1_num *m);

/** Compute the jacobi symbol (a|b). b must be positive and odd. */
static int cppethsecp256k1_num_jacobi(const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Compare the absolute value of two numbers. */
static int cppethsecp256k1_num_cmp(const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Test whether two number are equal (including sign). */
static int cppethsecp256k1_num_eq(const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Add two (signed) numbers. */
static void cppethsecp256k1_num_add(cppethsecp256k1_num *r, const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Subtract two (signed) numbers. */
static void cppethsecp256k1_num_sub(cppethsecp256k1_num *r, const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Multiply two (signed) numbers. */
static void cppethsecp256k1_num_mul(cppethsecp256k1_num *r, const cppethsecp256k1_num *a, const cppethsecp256k1_num *b);

/** Replace a number by its remainder modulo m. M's sign is ignored. The result is a number between 0 and m-1,
    even if r was negative. */
static void cppethsecp256k1_num_mod(cppethsecp256k1_num *r, const cppethsecp256k1_num *m);

/** Right-shift the passed number by bits bits. */
static void cppethsecp256k1_num_shift(cppethsecp256k1_num *r, int bits);

/** Check whether a number is zero. */
static int cppethsecp256k1_num_is_zero(const cppethsecp256k1_num *a);

/** Check whether a number is one. */
static int cppethsecp256k1_num_is_one(const cppethsecp256k1_num *a);

/** Check whether a number is strictly negative. */
static int cppethsecp256k1_num_is_neg(const cppethsecp256k1_num *a);

/** Change a number's sign. */
static void cppethsecp256k1_num_negate(cppethsecp256k1_num *r);

#endif

#endif
