#include <string.h>
#include <lib25519.h>
#include "../mlkem/ref/kem.h"
#include "xkem.h"
#include "params.h"
#include "../mlkem/ref/indcpa.h"
#include "../mlkem/ref/symmetric.h"
#include "../mlkem/ref/randombytes.h"
#include "../../mceliece348864/ref/pqcrypt.h"
#include "../../mceliece348864/ref/encrypt.h"
#include "../../mceliece348864/ref/api.h"
/*************************************************
 * Name:        crypto_xkem_keypair_derand
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 *              - const unsigned char *randomness: pointer to input random coins used as seed (of length 3*XWING_SYMBYTES bytes)
 *                                                 to deterministically generate all randomness
 **************************************************/
int crypto_xkem_keypair_derand(unsigned char *pk,
                                unsigned char *sk,
                                const unsigned char *randomness)
{
  crypto_mlkem_keypair(pk, sk, randomness);
  pk += MLKEM_PUBLICKEYBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  //randomness += 2 * XWING_SYMBYTES;


  //generate Mcelice key pair
  crypto_kem_keypair(pk,sk);

  //lib25519_nG_montgomery25519(pk, randomness);
  //memcpy(sk, randomness, DH_BYTES);
  //memcpy(sk + DH_BYTES, pk, DH_BYTES);
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_keypair
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
int crypto_xkem_keypair(unsigned char *pk,
                         unsigned char *sk)
{
  unsigned char buf[2 * XWING_SYMBYTES];
  randombytes(buf, 2 * XWING_SYMBYTES);
  return crypto_xkem_keypair_derand(pk, sk, buf);
}

/*************************************************
 * Name:        crypto_xkem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *pk:    pointer to input public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - const unsigned char *coins: pointer to input random coins used as seed (of length 2*XWING_SYMBYTES bytes)
 *                                            to deterministically generate all randomness
 **************************************************/
int crypto_xkem_enc_derand(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins)
{
  const unsigned char *m1;
  const unsigned char *m2;
  const unsigned char buf[2*DH_BYTES];

  m1 = coins;
  m2 = coins+DH_BYTES;

  unsigned char new[MLKEM_SYMBYTES];
  randombytes(new, MLKEM_SYMBYTES);
  indcpa_enc(ct, m1, pk, new);

  pk += MLKEM_PUBLICKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;

  lib25519_nG_montgomery25519(ct, m2);
  lib25519_dh(m2, pk, coins);

  memcpy(buf, m1, DH_BYTES);
  memcpy(buf+ DH_BYTES, m2, DH_BYTES);

  sha3_256(ss, buf, 64);
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 **************************************************/
int crypto_xkem_enc(unsigned char *ct,
                     unsigned char *ss,
                     const unsigned char *pk)
{
  unsigned char buf[2 * DH_BYTES];
  randombytes(buf, 2 * DH_BYTES);

  return crypto_xkem_enc_derand(ct, ss, pk, buf);
}

/*************************************************
 * Name:        crypto_xkem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - unsigned char *ss:        pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *ct:  pointer to input ciphertext (of length XWING_CIPHERTEXTKEYBYTES bytes)
 *              - const unsigned char *sk:  pointer to input secret key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
int crypto_xkem_dec(uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk)
{
  unsigned char buf[2 * DH_BYTES];
  unsigned char m1[DH_BYTES];
  unsigned char m2[DH_BYTES];

  indcpa_dec(m1, ct, sk);

  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;

  lib25519_dh(m2, ct, sk);
  sk += DH_BYTES;

  memcpy(buf, m1, DH_BYTES);
  memcpy(buf + DH_BYTES, m2, DH_BYTES);

  sha3_256(ss, buf, 64);
  return 0;
}
