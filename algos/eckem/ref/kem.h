#ifndef PQCRYPT_RSAKEM_H
#define PQCRYPT_RSAKEM_H

#define PQCRYPT_CRYPTO_SECRETKEYBYTES 32
#define PQCRYPT_CRYPTO_PUBLICKEYBYTES 65
#define PQCRYPT_CRYPTO_BYTES 32
#define PQCRYPT_CRYPTO_CIPHERTEXTBYTES 65

int PQCRYPT_crypto_eckem_keypair(unsigned char *pk, unsigned char *sk);
int PQCRYPT_crypto_eckem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int PQCRYPT_crypto_eckem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif