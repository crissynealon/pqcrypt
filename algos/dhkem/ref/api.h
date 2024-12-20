#ifndef API_H
#define API_H

#define CRYPTO_ALGNAME "dhkem"
#define CRYPTO_SECRETKEYBYTES 3040
#define CRYPTO_PUBLICKEYBYTES (4*320+32)
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 1472

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
