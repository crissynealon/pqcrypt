#ifndef PQCRYPT_RSAKEM_H
#define PQCRYPT_RSAKEM_H

#define PQCRYPT_CRYPTO_SECRETKEYBYTES 1224
#define PQCRYPT_CRYPTO_PUBLICKEYBYTES 294
#define PQCRYPT_CRYPTO_BYTES 256
#define PQCRYPT_CRYPTO_CIPHERTEXTBYTES 256

int PQCRYPT_crypto_rsakem_keypair(unsigned char *pk, unsigned char *sk);
int PQCRYPT_crypto_rsakem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int PQCRYPT_crypto_rsakem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif