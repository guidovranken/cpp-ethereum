/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_RECOVERY_MAIN_
#define _SECP256K1_MODULE_RECOVERY_MAIN_

#include "include/secp256k1_recovery.h"

static void cppethsecp256k1_ecdsa_recoverable_signature_load(const cppethsecp256k1_context* ctx, cppethsecp256k1_scalar* r, cppethsecp256k1_scalar* s, int* recid, const cppethsecp256k1_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(cppethsecp256k1_scalar) == 32) {
        /* When the cppethsecp256k1_scalar type is exactly 32 byte, use its
         * representation inside cppethsecp256k1_ecdsa_signature, as conversion is very fast.
         * Note that cppethsecp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        cppethsecp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        cppethsecp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void cppethsecp256k1_ecdsa_recoverable_signature_save(cppethsecp256k1_ecdsa_recoverable_signature* sig, const cppethsecp256k1_scalar* r, const cppethsecp256k1_scalar* s, int recid) {
    if (sizeof(cppethsecp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        cppethsecp256k1_scalar_get_b32(&sig->data[0], r);
        cppethsecp256k1_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int cppethsecp256k1_ecdsa_recoverable_signature_parse_compact(const cppethsecp256k1_context* ctx, cppethsecp256k1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    cppethsecp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    cppethsecp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    cppethsecp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        cppethsecp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int cppethsecp256k1_ecdsa_recoverable_signature_serialize_compact(const cppethsecp256k1_context* ctx, unsigned char *output64, int *recid, const cppethsecp256k1_ecdsa_recoverable_signature* sig) {
    cppethsecp256k1_scalar r, s;

    (void)ctx;
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    cppethsecp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    cppethsecp256k1_scalar_get_b32(&output64[0], &r);
    cppethsecp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int cppethsecp256k1_ecdsa_recoverable_signature_convert(const cppethsecp256k1_context* ctx, cppethsecp256k1_ecdsa_signature* sig, const cppethsecp256k1_ecdsa_recoverable_signature* sigin) {
    cppethsecp256k1_scalar r, s;
    int recid;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    cppethsecp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    cppethsecp256k1_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int cppethsecp256k1_ecdsa_sig_recover(const cppethsecp256k1_ecmult_context *ctx, const cppethsecp256k1_scalar *sigr, const cppethsecp256k1_scalar* sigs, cppethsecp256k1_ge *pubkey, const cppethsecp256k1_scalar *message, int recid) {
    unsigned char brx[32];
    cppethsecp256k1_fe fx;
    cppethsecp256k1_ge x;
    cppethsecp256k1_gej xj;
    cppethsecp256k1_scalar rn, u1, u2;
    cppethsecp256k1_gej qj;
    int r;

    if (cppethsecp256k1_scalar_is_zero(sigr) || cppethsecp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    cppethsecp256k1_scalar_get_b32(brx, sigr);
    r = cppethsecp256k1_fe_set_b32(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (cppethsecp256k1_fe_cmp_var(&fx, &cppethsecp256k1_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        cppethsecp256k1_fe_add(&fx, &cppethsecp256k1_ecdsa_const_order_as_fe);
    }
    if (!cppethsecp256k1_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    cppethsecp256k1_gej_set_ge(&xj, &x);
    cppethsecp256k1_scalar_inverse_var(&rn, sigr);
    cppethsecp256k1_scalar_mul(&u1, &rn, message);
    cppethsecp256k1_scalar_negate(&u1, &u1);
    cppethsecp256k1_scalar_mul(&u2, &rn, sigs);
    cppethsecp256k1_ecmult(ctx, &qj, &xj, &u2, &u1);
    cppethsecp256k1_ge_set_gej_var(pubkey, &qj);
    return !cppethsecp256k1_gej_is_infinity(&qj);
}

int cppethsecp256k1_ecdsa_sign_recoverable(const cppethsecp256k1_context* ctx, cppethsecp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, cppethsecp256k1_nonce_function noncefp, const void* noncedata) {
    cppethsecp256k1_scalar r, s;
    cppethsecp256k1_scalar sec, non, msg;
    int recid;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(cppethsecp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = cppethsecp256k1_nonce_function_default;
    }

    cppethsecp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !cppethsecp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        cppethsecp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            cppethsecp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!cppethsecp256k1_scalar_is_zero(&non) && !overflow) {
                if (cppethsecp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, &recid)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        cppethsecp256k1_scalar_clear(&msg);
        cppethsecp256k1_scalar_clear(&non);
        cppethsecp256k1_scalar_clear(&sec);
    }
    if (ret) {
        cppethsecp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int cppethsecp256k1_ecdsa_recover(const cppethsecp256k1_context* ctx, cppethsecp256k1_pubkey *pubkey, const cppethsecp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32) {
    cppethsecp256k1_ge q;
    cppethsecp256k1_scalar r, s;
    cppethsecp256k1_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(cppethsecp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    cppethsecp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    cppethsecp256k1_scalar_set_b32(&m, msg32, NULL);
    if (cppethsecp256k1_ecdsa_sig_recover(&ctx->ecmult_ctx, &r, &s, &q, &m, recid)) {
        cppethsecp256k1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

#endif
