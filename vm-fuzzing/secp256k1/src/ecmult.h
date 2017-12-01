/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_
#define _SECP256K1_ECMULT_

#include "num.h"
#include "group.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    cppethsecp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
#ifdef USE_ENDOMORPHISM
    cppethsecp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
#endif
} cppethsecp256k1_ecmult_context;

static void cppethsecp256k1_ecmult_context_init(cppethsecp256k1_ecmult_context *ctx);
static void cppethsecp256k1_ecmult_context_build(cppethsecp256k1_ecmult_context *ctx, const cppethsecp256k1_callback *cb);
static void cppethsecp256k1_ecmult_context_clone(cppethsecp256k1_ecmult_context *dst,
                                           const cppethsecp256k1_ecmult_context *src, const cppethsecp256k1_callback *cb);
static void cppethsecp256k1_ecmult_context_clear(cppethsecp256k1_ecmult_context *ctx);
static int cppethsecp256k1_ecmult_context_is_built(const cppethsecp256k1_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void cppethsecp256k1_ecmult(const cppethsecp256k1_ecmult_context *ctx, cppethsecp256k1_gej *r, const cppethsecp256k1_gej *a, const cppethsecp256k1_scalar *na, const cppethsecp256k1_scalar *ng);

#endif
