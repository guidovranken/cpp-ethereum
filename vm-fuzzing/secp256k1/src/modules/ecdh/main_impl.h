/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECDH_MAIN_
#define _SECP256K1_MODULE_ECDH_MAIN_

#include "include/secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

int cppethsecp256k1_ecdh_raw(const cppethsecp256k1_context* ctx, unsigned char *result, const cppethsecp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    cppethsecp256k1_gej res;
    cppethsecp256k1_ge pt;
    cppethsecp256k1_scalar s;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    cppethsecp256k1_pubkey_load(ctx, &pt, point);
    cppethsecp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || cppethsecp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        cppethsecp256k1_ecmult_const(&res, &pt, &s);
        cppethsecp256k1_ge_set_gej(&pt, &res);
        /* Output the point in compressed form.
         * Note we cannot use cppethsecp256k1_eckey_pubkey_serialize here since it does not
         * expect its output to be secret and has a timing sidechannel. */
        cppethsecp256k1_fe_normalize(&pt.x);
        cppethsecp256k1_fe_normalize(&pt.y);
        result[0] = 0x02 | cppethsecp256k1_fe_is_odd(&pt.y);
        cppethsecp256k1_fe_get_b32(&result[1], &pt.x);
        ret = 1;
    }

    cppethsecp256k1_scalar_clear(&s);
    return ret;
}

int cppethsecp256k1_ecdh(const cppethsecp256k1_context* ctx, unsigned char *result, const cppethsecp256k1_pubkey *point, const unsigned char *scalar) {
    unsigned char shared[33];
    cppethsecp256k1_sha256_t sha;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(result != NULL);

    if (!cppethsecp256k1_ecdh_raw(ctx, shared, point, scalar)) {
        return 0;
    }

    cppethsecp256k1_sha256_initialize(&sha);
    cppethsecp256k1_sha256_write(&sha, shared, sizeof(shared));
    cppethsecp256k1_sha256_finalize(&sha, result);
    return 1;
}

#endif
