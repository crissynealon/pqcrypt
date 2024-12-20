#include <stdlib.h>
#include "symmetric.h"
#include "fips202.h"

/*************************************************
* Name:        mlkem_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the mlkem context.
*
* Arguments:   - uint64_t *s:                     pointer to (uninitialized) output Keccak state
*              - const unsigned char *input:      pointer to MLKEM_SYMBYTES input to be absorbed into s
*              - unsigned char i                  additional byte of input
*              - unsigned char j                  additional byte of input
**************************************************/
void mlkem_shake128_absorb(keccak_state *s, const unsigned char *input, unsigned char x, unsigned char y)
{
  unsigned char extseed[MLKEM_SYMBYTES+2];
  int i;

  for(i=0;i<MLKEM_SYMBYTES;i++)
    extseed[i] = input[i];
  extseed[i++] = x;
  extseed[i]   = y;
  shake128_absorb(s->s, extseed, MLKEM_SYMBYTES+2);
}

/*************************************************
* Name:        mlkem_shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - unsigned char *output:      pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s:            pointer to in/output Keccak state
**************************************************/
void mlkem_shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, keccak_state *s)
{
  shake128_squeezeblocks(output, nblocks, s->s);
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - unsigned char *output:      pointer to output
*              - unsigned long long outlen:  number of requested output bytes
*              - const unsigned char * key:  pointer to the key (of length MLKEM_SYMBYTES)
*              - const unsigned char nonce:  single-byte nonce (public PRF input)
**************************************************/
void shake256_prf(unsigned char *output, unsigned long long outlen, const unsigned char *key, const unsigned char nonce)
{
  unsigned char extkey[MLKEM_SYMBYTES+1];
  size_t i;

  for(i=0;i<MLKEM_SYMBYTES;i++)
    extkey[i] = key[i];
  extkey[i] = nonce;

  shake256(output, outlen, extkey, MLKEM_SYMBYTES+1);
}

void shake256_rkprf(unsigned char *out, const unsigned char *key, const unsigned char *input)
{
  unsigned char extkey[MLKEM_SYMBYTES+MLKEM_CIPHERTEXTBYTES];
  size_t i;

  for(i=0;i<MLKEM_SYMBYTES;i++)
    extkey[i] = key[i];
  for(i=0;i<MLKEM_CIPHERTEXTBYTES;i++)
    extkey[i+MLKEM_SYMBYTES] = input[i];

  shake256(out, MLKEM_SYMBYTES, extkey, MLKEM_SYMBYTES+MLKEM_CIPHERTEXTBYTES);
}