#ifndef PQCRYPT_H
#define PQCRYPT_H
/**
 * @file pqcrypt.h
 * @brief The header only used by the pqcrypt repro, just for standard interface
 */

#include <stdint.h>
#include "api.h"
#include "params.h"

#define cffi_crypto_keygen PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_mceliece6688128f_encrypt
#define cffi_crypto_decrypt PQCRYPT_mceliece6688128f_decrypt

#define CFFI_CRYPTO_ALGNAME        PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_ALGNAME
#define CFFI_CRYPTO_BYTES          PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES
#define CFFI_CRYPTO_CIPHERTEXTBYTES PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CFFI_CRYPTO_PUBLICKEYBYTES  PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CFFI_CRYPTO_SECRETKEYBYTES  PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES
#define CFFI_CRYPTO_PLAINTEXTBYTES  SYS_N

int PQCRYPT_mceliece6688128f_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk);
int PQCRYPT_mceliece6688128f_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

#endif