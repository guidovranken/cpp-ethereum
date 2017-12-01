/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECKEY_
#define _SECP256K1_ECKEY_

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int cppethsecp256k1_eckey_pubkey_parse(cppethsecp256k1_ge *elem, const unsigned char *pub, size_t size);
static int cppethsecp256k1_eckey_pubkey_serialize(cppethsecp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int cppethsecp256k1_eckey_privkey_tweak_add(cppethsecp256k1_scalar *key, const cppethsecp256k1_scalar *tweak);
static int cppethsecp256k1_eckey_pubkey_tweak_add(const cppethsecp256k1_ecmult_context *ctx, cppethsecp256k1_ge *key, const cppethsecp256k1_scalar *tweak);
static int cppethsecp256k1_eckey_privkey_tweak_mul(cppethsecp256k1_scalar *key, const cppethsecp256k1_scalar *tweak);
static int cppethsecp256k1_eckey_pubkey_tweak_mul(const cppethsecp256k1_ecmult_context *ctx, cppethsecp256k1_ge *key, const cppethsecp256k1_scalar *tweak);

#endif
