#include "pqcrypt.h"
#include "owcpa.h"
#include "params.h"
#include "sample.h"
#include "randombytes.h"
#include <stdint.h>

/**
 * @brief ntruhrss701 encryption function
 *
 * @param[out] ct    Output ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  pt    Input plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  pk    Input public key buffer (KYBER_INDCPA_PUBLICKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_ntruhrss701_encrypt(uint8_t *ct, const uint8_t *pt,
                                   const uint8_t *pk) {
    poly r, m;
    uint8_t rm_seed[NTRU_SAMPLE_RM_BYTES];
    // Generate random seed
    randombytes(rm_seed, NTRU_SAMPLE_RM_BYTES);
    // Sample polynomials r and m
    sample_rm(&r, &m, rm_seed);
    // Convert r to Zq
    poly_Z3_to_Zq(&r);
    // Perform encryption
    owcpa_enc(ct, &r, &m, pk);

    return 0;
}

/**
 * @brief NTRU decryption function
 *
 * @param[out] pt    Output plaintext (2 * NTRU_PACK_TRINARY_BYTES bytes)
 * @param[in]  ct    Input ciphertext
 * @param[in]  sk    Input secret key (NTRU_SECRETKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_ntruhrss701_decrypt(uint8_t *pt, const uint8_t *ct,
                                   const uint8_t *sk) {
  // owcpa_dec returns 0 on success, non-zero on failure
  // which matches our desired return value convention
  return owcpa_dec(pt, ct, sk);
}