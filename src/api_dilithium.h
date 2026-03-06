#ifndef PQCLEAN_MLDSA65_CLEAN_API_H
#define PQCLEAN_MLDSA65_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES 1952
#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES 4032
#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES          3309

#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_ALGNAME "ML-DSA-65"

// Backward compatibility aliases
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES

/**
 * Generate a keypair for ML-DSA-65 signature scheme
 */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Sign a message using ML-DSA-65
 */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen,
    const uint8_t *sk
);

/**
 * Verify a signed message using ML-DSA-65
 */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen,
    const uint8_t *pk
);

// Backward compatibility aliases for function names
#define PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair
#define PQCLEAN_DILITHIUM3_CLEAN_crypto_sign PQCLEAN_MLDSA65_CLEAN_crypto_sign
#define PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_open PQCLEAN_MLDSA65_CLEAN_crypto_sign_open

#endif /* PQCLEAN_MLDSA65_CLEAN_API_H */