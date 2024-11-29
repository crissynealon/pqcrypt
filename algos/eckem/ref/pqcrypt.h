#ifndef PQCRYPT_H
#define PQCRYPT_H
/**
 * @file pqcrypt.h
 * @brief The header only used by the pqcrypt repro, just for standard interface
 */

#include <stdint.h>
#include "api.h"
#include "kem.h"

#define cffi_crypto_keygen PQCRYPT_crypto_eckem_keypair
#define cffi_crypto_kem_encaps PQCRYPT_crypto_eckem_enc
#define cffi_crypto_kem_decaps PQCRYPT_crypto_eckem_dec
#define cffi_crypto_encrypt PQCRYPT_eckem_encrypt
#define cffi_crypto_decrypt PQCRYPT_eckem_decrypt

#define PQCRYPT_CRYPTO_PLAINTEXTBYTES 190
#define CFFI_CRYPTO_ALGNAME  CRYPTO_ALGNAME
#define CFFI_CRYPTO_BYTES    PQCRYPT_CRYPTO_BYTES
#define CFFI_CRYPTO_CIPHERTEXTBYTES  PQCRYPT_CRYPTO_CIPHERTEXTBYTES
#define CFFI_CRYPTO_PUBLICKEYBYTES   PQCRYPT_CRYPTO_PUBLICKEYBYTES
#define CFFI_CRYPTO_SECRETKEYBYTES   PQCRYPT_CRYPTO_SECRETKEYBYTES
#define CFFI_CRYPTO_PLAINTEXTBYTES   PQCRYPT_CRYPTO_PLAINTEXTBYTES

int PQCRYPT_eckem_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk);
int PQCRYPT_eckem_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

#endif
