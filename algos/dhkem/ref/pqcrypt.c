#include <lib25519.h>
#include "pqcrypt.h"
#include "kem.h"
#include "randombytes.h"

/**
 * @brief DH encryption function
 *
 * @param[out] ct    Output ciphertext (DH_BYTES bytes)
 * @param[in]  pt    Input plaintext (DH_BYTES bytes for secret key)
 * @param[in]  pk    Input recipient's public key (DH_BYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_dhkem_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    // Perform DH key exchange using pt as secret key and pk as public key
    lib25519_dh(ct, pk, pt);
    return 0;
}

/**
 * @brief DH decryption function
 *
 * @param[out] pt    Output plaintext (DH_BYTES bytes)
 * @param[in]  ct    Input ciphertext (other party's public key, DH_BYTES bytes)
 * @param[in]  sk    Input secret key (DH_BYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_dhkem_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    // Perform DH key exchange using sk as secret key and ct as other's public key
    lib25519_dh(pt, ct, sk);
    return 0;
}

/**
 * @brief Generate keypair for dhkem
 *
 * @param[out] pk    Output public key (DH_BYTES bytes)
 * @param[out] sk    Output secret key (DH_BYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    // Generate random secret key
    unsigned char randomness[DH_BYTES];
    randombytes(randomness, DH_BYTES);

    // Generate keypair
    crypto_dkem_keypair(pk, sk, randomness);

    return 0;
}


/**
 * @brief Encapsulation function for dhkem
 *
 * @param[out] ct    Output ciphertext (DH_BYTES bytes)
 * @param[out] ss    Output shared secret (MESSAGE_BYTES bytes)
 * @param[in]  pk    Input public key (DH_BYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    // Generate random coins
    unsigned char coins[DH_BYTES];
    randombytes(coins, DH_BYTES);
    // Perform encapsulation
    crypto_dkem_enc(ct, ss, pk, coins);

    return 0;
}

/**
 * @brief Decapsulation function for dhkem
 *
 * @param[out] ss    Output shared secret (MESSAGE_BYTES bytes)
 * @param[in]  ct    Input ciphertext (DH_BYTES bytes)
 * @param[in]  sk    Input secret key (DH_BYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    // Perform decapsulation
    crypto_dkem_dec(ss, ct, sk);

    return 0;
}
