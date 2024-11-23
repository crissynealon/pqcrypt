#include "pqcrypt.h"
#include "hqc.h"
#include "parameters.h"
#include "randombytes.h"

int PQCRYPT_HQC128_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    // Generate random theta
    uint8_t theta[SEED_BYTES];
    randombytes(theta, SEED_BYTES);

    // Split ct into u and v components
    uint64_t *u = (uint64_t *)ct;
    uint64_t *v = (uint64_t *)(ct + VEC_N_SIZE_64 * sizeof(uint64_t));

    // Call the original encryption function
    PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(u, v, (uint8_t*)pt, theta, pk);

    return 0;
}

int PQCRYPT_HQC128_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    // Extract u and v from ct
    const uint64_t *u = (const uint64_t *)ct;
    const uint64_t *v = (const uint64_t *)(ct + VEC_N_SIZE_64 * sizeof(uint64_t));

    // Buffer for sigma (retrieved from secret key during decryption)
    uint8_t sigma[SEED_BYTES];

    // Call the original decryption function
    PQCLEAN_HQC128_CLEAN_hqc_pke_decrypt(pt, sigma, u, v, sk);

    return 0;
}