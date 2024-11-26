#include "pqcrypt.h"
#include "common.h"
#include "params.h"
#include "fips202.h"
#include "randombytes.h"
#include <stdint.h>

/**
 * @brief frodokem640aes encryption function
 *
 * @param[out] ct    Output ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  pt    Input plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  pk    Input public key buffer (KYBER_INDCPA_PUBLICKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_frodokem640aes_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) / 8];

    uint16_t B[PARAMS_N * PARAMS_NBAR] = {0};
    uint16_t V[PARAMS_NBAR * PARAMS_NBAR] = {0};
    uint16_t C[PARAMS_NBAR * PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N * PARAMS_NBAR] = {0};
    uint16_t Sp[(2 * PARAMS_N + PARAMS_NBAR)*PARAMS_NBAR] = {0};
    uint16_t *Ep = &Sp[PARAMS_N * PARAMS_NBAR];
    uint16_t *Epp = &Sp[2 * PARAMS_N * PARAMS_NBAR];
    uint8_t G2in[BYTES_PKHASH + BYTES_MU];
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[BYTES_PKHASH];
    uint8_t G2out[2 * CRYPTO_BYTES];
    uint8_t *seedSE = &G2out[0];
    uint8_t shake_input_seedSE[1 + CRYPTO_BYTES];

    shake(pkh, BYTES_PKHASH, pk, CRYPTO_PUBLICKEYBYTES);
    memcpy(mu, pt, BYTES_MU);
    shake(G2out, CRYPTO_BYTES + CRYPTO_BYTES, G2in, BYTES_PKHASH + BYTES_MU);

    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, CRYPTO_BYTES);
    shake((uint8_t *)Sp, (2 * PARAMS_N + PARAMS_NBAR) * PARAMS_NBAR * sizeof(uint16_t), shake_input_seedSE, 1 + CRYPTO_BYTES);
    for (size_t i = 0; i < (2 * PARAMS_N + PARAMS_NBAR) * PARAMS_NBAR; i++) {
        Sp[i] = LE_TO_UINT16(Sp[i]);
    }
    sample_n(Sp, PARAMS_N * PARAMS_NBAR);
    sample_n(Ep, PARAMS_N * PARAMS_NBAR);
    mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);
    pack(ct_c1, (PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) / 8, Bp, PARAMS_N * PARAMS_NBAR, PARAMS_LOGQ);

    sample_n(Epp, PARAMS_NBAR * PARAMS_NBAR);
    unpack(B, PARAMS_N * PARAMS_NBAR, pk_b, CRYPTO_PUBLICKEYBYTES - BYTES_SEED_A, PARAMS_LOGQ);
    mul_add_sb_plus_e(V, B, Sp, Epp);

    key_encode(C, (uint16_t *)mu);
    add(C, V, C);
    pack(ct_c2, (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8, C, PARAMS_NBAR * PARAMS_NBAR, PARAMS_LOGQ);

    return 0;
}

/**
 * @brief frodokem640aes decryption function
 *
 * @param[out] pt    Output plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
 * @param[in]  ct    Input ciphertext buffer (KYBER_INDCPA_BYTES bytes)
 * @param[in]  sk    Input secret key buffer (KYBER_INDCPA_SECRETKEYBYTES bytes)
 * @return int       Returns 0 for success, non-zero for failure
 */
int PQCRYPT_frodokem640aes_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    uint16_t W[PARAMS_NBAR * PARAMS_NBAR] = {0};
    uint16_t C[PARAMS_NBAR * PARAMS_NBAR] = {0};
    uint16_t Bp[PARAMS_N * PARAMS_NBAR] = {0};
    uint16_t S[PARAMS_N * PARAMS_NBAR];
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) / 8];
    const uint8_t *sk_S = &sk[CRYPTO_BYTES + CRYPTO_PUBLICKEYBYTES];

    for (size_t i = 0; i < PARAMS_N * PARAMS_NBAR; i++) {
        S[i] = sk_S[2 * i] | (sk_S[2 * i + 1] << 8);
    }

    unpack(Bp, PARAMS_N * PARAMS_NBAR, ct_c1, (PARAMS_LOGQ * PARAMS_N * PARAMS_NBAR) / 8, PARAMS_LOGQ);
    unpack(C, PARAMS_NBAR * PARAMS_NBAR, ct_c2, (PARAMS_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8, PARAMS_LOGQ);
    mul_bs(W, Bp, S);
    sub(W, C, W);
    key_decode((uint16_t *)pt, W);

    clear_bytes((uint8_t *)W, PARAMS_NBAR * PARAMS_NBAR * sizeof(uint16_t));
    clear_bytes((uint8_t *)S, PARAMS_N * PARAMS_NBAR * sizeof(uint16_t));

    return 0;

}