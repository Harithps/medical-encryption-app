#ifndef PQCLEAN_MLKEM768_CLEAN_API_H
#define PQCLEAN_MLKEM768_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES  2400
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES  1184
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES           32

#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_ALGNAME "ML-KEM-768"

// Backward compatibility aliases
#define PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES           PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES

/**
 * Generate a keypair for ML-KEM-768 KEM
 */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Encapsulate a shared secret using ML-KEM-768
 */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * Decapsulate a shared secret using ML-KEM-768
 */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Backward compatibility aliases for function names
#define PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair
#define PQCLEAN_KYBER768_CLEAN_crypto_kem_enc PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc
#define PQCLEAN_KYBER768_CLEAN_crypto_kem_dec PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec

#endif /* PQCLEAN_MLKEM768_CLEAN_API_H */