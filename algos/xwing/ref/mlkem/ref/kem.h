#ifndef KEM_H
#define KEM_H

#include <stdint.h>

void crypto_mlkem_keypair(unsigned char *pk,
                    unsigned char *sk,
                    const unsigned char *randomness);

void crypto_mlkem_enc(unsigned char *c,
                unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

void crypto_mlkem_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

#endif
