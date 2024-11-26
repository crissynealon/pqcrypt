#ifndef PQCRYPT_H
#define PQCRYPT_H
/**
 * @file pqcrypt.h
 * @brief The header only used by the pqcrypt repro, just for standard interface
 */

#include <stdint.h>
#include "api.h"
#include "params.h"

#define cffi_crypto_keygen PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
#define cffi_crypto_kem_encaps PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc
#define cffi_crypto_kem_decaps PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec
#define cffi_crypto_encrypt PQCRYPT_mlkem512_encrypt
#define cffi_crypto_decrypt PQCRYPT_mlkem512_decrypt

#define CFFI_CRYPTO_ALGNAME        PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME
#define CFFI_CRYPTO_BYTES          PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#define CFFI_CRYPTO_CIPHERTEXTBYTES PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define CFFI_CRYPTO_PUBLICKEYBYTES  PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CFFI_CRYPTO_SECRETKEYBYTES  PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#define CFFI_CRYPTO_PLAINTEXTBYTES  KYBER_INDCPA_MSGBYTES

int PQCRYPT_MLKEM512_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk);
int PQCRYPT_MLKEM512_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk);

#endif