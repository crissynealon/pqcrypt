#ifndef PQCRYPT_H
#define PQCRYPT_H
/**
 * @file pqcrypt.h
 * @brief The header only used by the pqcrypt repro, just for standard interface
 */

#include <stdint.h>
#include "api.h"
#include "params.h"

#define cffi_crypto_keygen crypto_kem_keypair
#define cffi_crypto_kem_encaps crypto_kem_enc
#define cffi_crypto_kem_decaps crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_kyber512_encrypt
#define cffi_crypto_decrypt PQCRYPT_kyber512_decrypt

#define CFFI_CRYPTO_ALGNAME        CRYPTO_ALGNAME
#define CFFI_CRYPTO_BYTES          CRYPTO_BYTES
#define CFFI_CRYPTO_CIPHERTEXTBYTES CRYPTO_CIPHERTEXTBYTES
#define CFFI_CRYPTO_PUBLICKEYBYTES  CRYPTO_PUBLICKEYBYTES
#define CFFI_CRYPTO_SECRETKEYBYTES  CRYPTO_SECRETKEYBYTES
#define CFFI_CRYPTO_PLAINTEXTBYTES  KYBER_INDCPA_MSGBYTES

int PQCRYPT_kyber512_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk);
int PQCRYPT_kyber512_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

#endif
