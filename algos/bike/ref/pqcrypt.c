// #include "randombytes.h"
// #include "pqcrypt.h"
// // #include "params.h"
// #include "bike_defs.h"
// #include "defs.h"
// #include "types.h"
// #include "cleanup.h"
// #include <stdint.h>
// #include "decode.h"
// #include "gf2x.h"
// #include "sampling.h"
// #include "sha.h"

// /**
//  * @brief bike encryption function
//  *
//  * @param[out] ct    Output ciphertext buffer (sizeof(ct_t) bytes)
//  * @param[in]  pt    Input plaintext (L_BYTES bytes, typically 256 bits/32 bytes)
//  * @param[in]  pk    Input public key (R_BYTES bytes)
//  * @return int       Returns 0 for success, non-zero for failure
//  */
// int PQCRYPT_bike_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
//     ct_t *bike_ct = (ct_t *)ct;
//     const m_t *bike_m = (const m_t *)pt;
//     pk_t bike_pk;

//     // 复制公钥到对齐的结构体
//     bike_memcpy(&bike_pk, pk, sizeof(pk_t));

//     // 生成error vector通过H函数
//     DEFER_CLEANUP(pad_e_t e, pad_e_cleanup);
//     if(function_h(&e, bike_m, &bike_pk) != SUCCESS) {
//         return -1;
//     }

//     ret_t ret = encrypt(bike_ct, &error, bike_pk, bike_m);
//     if(ret != SUCCESS) {
//         return -1;
//     }
//     return 0;
// }

// /**
//  * @brief bike decryption function
//  *
//  * @param[out] pt    Output plaintext buffer (KYBER_INDCPA_MSGBYTES bytes)
//  * @param[in]  ct    Input ciphertext buffer (KYBER_INDCPA_BYTES bytes)
//  * @param[in]  sk    Input secret key buffer (KYBER_INDCPA_SECRETKEYBYTES bytes)
//  * @return int       Returns 0 for success, non-zero for failure
//  */
// int PQCRYPT_bike_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
//     return 0;  // Success
// }