#include "pqcrypt.h"
#include "encrypt.h"
#include "decrypt.h"

int PQCRYPT_mceliece348864_encrypt(uint8_t *ct, uint8_t *pt, const uint8_t *pk) {
    encrypt(ct, pk, pt);
    return 0;  // Success
}

int PQCRYPT_mceliece348864_decrypt(uint8_t *pt, const uint8_t *ct, const unsigned char *sk) {
    // Call the core decryption function
    decrypt(pt, sk+40, ct);
    return 0;  // Success
}
