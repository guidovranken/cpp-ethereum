/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_HASH_
#define _SECP256K1_HASH_

#include <stddef.h>
#include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} cppethsecp256k1_sha256_t;

void cppethsecp256k1_sha256_initialize(cppethsecp256k1_sha256_t *hash);
void cppethsecp256k1_sha256_write(cppethsecp256k1_sha256_t *hash, const unsigned char *data, size_t size);
void cppethsecp256k1_sha256_finalize(cppethsecp256k1_sha256_t *hash, unsigned char *out32);

typedef struct {
    cppethsecp256k1_sha256_t inner, outer;
} cppethsecp256k1_hmac_sha256_t;

void cppethsecp256k1_hmac_sha256_initialize(cppethsecp256k1_hmac_sha256_t *hash, const unsigned char *key, size_t size);
void cppethsecp256k1_hmac_sha256_write(cppethsecp256k1_hmac_sha256_t *hash, const unsigned char *data, size_t size);
void cppethsecp256k1_hmac_sha256_finalize(cppethsecp256k1_hmac_sha256_t *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} cppethsecp256k1_rfc6979_hmac_sha256_t;

void cppethsecp256k1_rfc6979_hmac_sha256_initialize(cppethsecp256k1_rfc6979_hmac_sha256_t *rng, const unsigned char *key, size_t keylen);
void cppethsecp256k1_rfc6979_hmac_sha256_generate(cppethsecp256k1_rfc6979_hmac_sha256_t *rng, unsigned char *out, size_t outlen);
void cppethsecp256k1_rfc6979_hmac_sha256_finalize(cppethsecp256k1_rfc6979_hmac_sha256_t *rng);

# ifdef __cplusplus
}
# endif

#endif
