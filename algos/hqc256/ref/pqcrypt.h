#ifndef PQCRYPT_H
#define PQCRYPT_H
/**
 * @file pqcrypt.h
 * @brief The header only used by the pqcrypt repro, just for standard interface
 */

#include <stdint.h>
#include "api.h"

#define cffi_crypto_keygen PQCLEAN_HQC256_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_HQC256_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_HQC256_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_HQC256_encrypt
#define cffi_crypto_decrypt PQCRYPT_HQC256_decrypt

// add msg length define
#define PQCLEAN_HQC256_CLEAN_CRYPTO_PLAINTEXTBYTES               16

#define CRYPTO_ALGNAME        PQCLEAN_HQC256_CLEAN_CRYPTO_ALGNAME
#define CRYPTO_BYTES          PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CRYPTO_PUBLICKEYBYTES  PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES  PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_PLAINTEXTBYTES  PQCLEAN_HQC256_CLEAN_CRYPTO_PLAINTEXTBYTES

int PQCRYPT_HQC256_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk);
int PQCRYPT_HQC256_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

#endif
