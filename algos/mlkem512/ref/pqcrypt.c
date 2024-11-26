#include "randombytes.h"
#include "pqcrypt.h"
#include "indcpa.h"
#include <stdint.h>

/**
 * @brief MLKEM512 encryption function
 *
 * @param[out] ct    Output ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  pt    Input plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  pk    Input public key buffer (KYBER_INDCPA_PUBLICKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_mlkem512_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    // Generate random coins
    uint8_t coins[KYBER_SYMBYTES];
    randombytes(coins, KYBER_SYMBYTES);

    // Call the core encryption function
    PQCLEAN_MLKEM512_CLEAN_indcpa_enc(ct, pt, pk, coins);

    return 0;  // Success
}

/**
 * @brief MLKEM512 decryption function
 *
 * @param[out] pt    Output plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  ct    Input ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  sk    Input secret key buffer (KYBER_INDCPA_SECRETKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_mlkem512_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    // Call the core decryption function
    PQCLEAN_MLKEM512_CLEAN_indcpa_dec(pt, ct, sk);

    return 0;  // Success
}