#include "randombytes.h"
#include "pqcrypt.h"
#include "params.h"
#include "encrypt.h"
#include "decrypt.h"

#include <stdint.h>

/**
 * @brief mceliece348864 encryption function
 *
 * @param[out] ct    Output ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  pt    Input plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  pk    Input public key buffer (KYBER_INDCPA_PUBLICKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_mceliece348864_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    syndrome(ct, pk, pt);

    return 0;  // Return 0 to indicate success
}
/**
 * @brief mceliece348864 decryption function
 *
 * @param[out] pt    Output plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  ct    Input ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  sk    Input secret key buffer (KYBER_INDCPA_SECRETKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_mceliece348864_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    // Call the core decryption function
    decrypt(pt, ct, sk);
    return 0;  // Success
}