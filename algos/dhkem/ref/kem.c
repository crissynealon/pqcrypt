#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <lib25519.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "derivekeypair.h"
#include "extractexpand.h"

void crypto_dkem_keypair(unsigned char *pk,
                         unsigned char *sk,
                         const unsigned char *randomness)
{
    // *sk = *randomness;
    memcpy(sk, randomness, DH_BYTES);
    lib25519_nG_montgomery25519(pk, sk);
}

void crypto_dkem_enc(unsigned char *c,
                     unsigned char *k,
                     const unsigned char *pk,
                     const unsigned char *coins)
{
    unsigned char skE[DH_BYTES];// dh[DH_BYTES], kemContext[KEM_CONTEXT_BYTES];
    *skE = *coins;
    lib25519_nG_montgomery25519(c, skE);
    //deriveKeyPair(skE, c, coins);
    lib25519_dh(k, pk, skE);
    //memcpy(kemContext, c, DH_BYTES);
    //memcpy(kemContext + DH_BYTES, pk, DH_BYTES);
    //extractAndExpand(m, dh, kemContext);
    //lib25519_dh(kemContext, pk, skE);

}

void crypto_dkem_dec(unsigned char *k,
                     const unsigned char *c,
                     const unsigned char *sk)
{
    //unsigned char pk[DH_BYTES], dh[DH_BYTES], kemContext[KEM_CONTEXT_BYTES];
    lib25519_dh(k, c, sk);
    //lib25519_nG_montgomery25519(pk, sk);
    //memcpy(kemContext, c, DH_BYTES);
    //memcpy(kemContext + DH_BYTES, pk, DH_BYTES);
    //extractAndExpand(k, dh, kemContext);
}
