#ifndef API_H
#define API_H
#include "kem.h"

#define CRYPTO_ALGNAME "eckem"
#define CRYPTO_SECRETKEYBYTES PQCRYPT_CRYPTO_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES PQCRYPT_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_BYTES PQCRYPT_CRYPTO_BYTES
#define CRYPTO_CIPHERTEXTBYTES PQCRYPT_CRYPTO_CIPHERTEXTBYTES

int crypto_eckem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_eckem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_eckem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
