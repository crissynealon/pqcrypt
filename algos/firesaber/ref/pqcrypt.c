#include "pqcrypt.h"
#include "randombytes.h"
#include "SABER_indcpa.h"
#include "SABER_params.h"

/**
 * @brief SABER encryption function
 *
 * @param[out] ct    Output ciphertext buffer (SABER_CIPHERTEXTBYTES bytes)
 * @param[in]  pt    Input plaintext buffer (SABER_MSGBYTES bytes)
 * @param[in]  pk    Input public key buffer (SABER_PUBLICKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_SABER_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    // Generate random noise seed
    uint8_t noise_seed[SABER_SEEDBYTES];
    randombytes(noise_seed, SABER_SEEDBYTES);
    // Call the core encryption function
    indcpa_kem_enc(pt, noise_seed, pk, ct);

    return 0;  // Success
}

/**
 * @brief SABER decryption function
 *
 * @param[out] pt    Output plaintext buffer (SABER_MSGBYTES bytes)
 * @param[in]  ct    Input ciphertext buffer (SABER_CIPHERTEXTBYTES bytes)
 * @param[in]  sk    Input secret key buffer (SABER_SECRETKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_SABER_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    // Call the core decryption function
    indcpa_kem_dec(sk, ct, pt);

    return 0;  // Success
}
