#include <string.h>
#include <lib25519.h>
#include "../mlkem/ref/kem.h"
#include "xkem.h"
#include "params.h"
#include "../mlkem/ref/randombytes.h"
#include "../mlkem/ref/symmetric.h"
#include <openssl/sha.h>


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>



int pbkdf2_hmac(const unsigned char *password, size_t password_len,
                const unsigned char *salt, size_t salt_len,
                int iterations, size_t key_len, unsigned char *out_key) {
    const EVP_MD *md = EVP_sha256();  // 指定散列算法，这里使用 SHA-256

    // 调用 PKCS5_PBKDF2_HMAC 函数进行密钥推导
    int success = PKCS5_PBKDF2_HMAC((const char *)password, password_len,
                                    salt, salt_len, iterations, md, key_len, out_key);
    return success;
}




uint8_t* xor_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t* result = malloc(len);
    if (!result) return NULL;

    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

uint8_t* F(const uint8_t* key, size_t len_key, int n) {
    size_t t = len_key / n;
    uint8_t* key_new = malloc(3 * t * SHA256_DIGEST_LENGTH); // 3 hashes per t bytes
    if (!key_new) return 0;

    for (size_t i = 0; i < len_key; i += t) {
        for (int j = 0; j < 3; j++) {
            uint8_t buffer[t + 1];
            buffer[0] = j;
            memcpy(buffer + 1, key + i, t);
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, buffer, sizeof(buffer));
            SHA256_Final(key_new + (i / t * 3 + j) * SHA256_DIGEST_LENGTH, &ctx);
        }
    }

    return key_new;
}


int main() {
    const char *password = "secret_password";
    const size_t password_len = strlen(password);
    unsigned char salt[16];

    // 生成随机盐
    if (!RAND_bytes(salt, sizeof(salt))) {
        fprintf(stderr, "Error generating random salt.\n");
        return 1;
    }

    const int iterations = 100000;  // 迭代次数
    const size_t key_len = 32;      // 生成的密钥长度，32字节对应256位
    unsigned char out_key[key_len];

    // 生成密钥
    if (!pbkdf2_hmac((const unsigned char *)password, password_len, salt, sizeof(salt),
                     iterations, key_len, out_key)) {
        fprintf(stderr, "Error deriving key.\n");
        return 1;
    }

    printf("Derived key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", out_key[i]);
    }
    printf("\n");

    return 0;
}



uint8_t* dual_prf(const uint8_t* key1, size_t len1, const uint8_t* key2, size_t len2) {
    unsigned char prf1_output[32], prf2_output[32];
    prf(key1, len1, (unsigned char*) "2", 1, prf1_output);
    prf(key2, len2, (unsigned char*) "1", 1, prf2_output);

    uint8_t* key1_f = F(key1, len1, 3);
    uint8_t* key2_f = F(key2, len2, 3);
    uint8_t* result = xor_bytes(prf1_output, prf2_output, 32);

    free(key1_f);
    free(key2_f);

    return result;
}




/*************************************************
 * Name:        crypto_xkem_keypair_derand
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 *              - const unsigned char *randomness: pointer to input random coins used as seed (of length 3*XWING_SYMBYTES bytes)
 *                                                 to deterministically generate all randomness
 **************************************************/
int crypto_xkem_keypair_derand(unsigned char *pk,
                                unsigned char *sk,
                                const unsigned char *randomness)
{
  crypto_mlkem_keypair(pk, sk, randomness);
  pk += MLKEM_PUBLICKEYBYTES;
  sk += MLKEM_SECRETKEYBYTES;
  randomness += 2 * XWING_SYMBYTES;
  lib25519_nG_montgomery25519(pk, randomness);
  memcpy(sk, randomness, DH_BYTES);
  memcpy(sk + DH_BYTES, pk, DH_BYTES);
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_keypair
 *
 * Description: Generates public and private key for the CCA-secure
 *              X-Wing key encapsulation mechanism
 *
 * Arguments:   - unsigned char *pk:               pointer to output public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - unsigned char *sk:               pointer to output private key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
int crypto_xkem_keypair(unsigned char *pk,
                         unsigned char *sk)
{
  unsigned char buf[3 * DH_BYTES];
  randombytes(buf, 3 * DH_BYTES);
  return crypto_xkem_keypair_derand(pk, sk, buf);
}

/*************************************************
 * Name:        crypto_xkem_enc_derand
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *pk:    pointer to input public key (of length XWING_PUBLICKEYBYTES bytes)
 *              - const unsigned char *coins: pointer to input random coins used as seed (of length 2*XWING_SYMBYTES bytes)
 *                                            to deterministically generate all randomness
 **************************************************/


uint8_t* dual_prf(const uint8_t* key1, size_t len1, const uint8_t* key2, size_t len2) {
    unsigned char prf1_output[32], prf2_output[32];
    prf(key1, len1, (unsigned char*) "2", 1, prf1_output);
    prf(key2, len2, (unsigned char*) "1", 1, prf2_output);

    uint8_t* key1_f = F(key1, len1, 3);
    uint8_t* key2_f = F(key2, len2, 3);
    uint8_t* result = xor_bytes(prf1_output, prf2_output, 32);

    free(key1_f);
    free(key2_f);

    return result;
}




int crypto_xkem_enc_derand(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins)
{
  unsigned char buffer[XWING_PRFINPUT];
  unsigned char *bufferPointer = buffer;

  //memcpy(buffer, XWING_LABEL, 6);
  //bufferPointer += 6;

  crypto_mlkem_enc(ct, bufferPointer, pk, coins);

  pk += MLKEM_PUBLICKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  coins += DH_BYTES;
  bufferPointer += MLKEM_SSBYTES;

  lib25519_nG_montgomery25519(ct, coins);
  lib25519_dh(bufferPointer, pk, coins);
  bufferPointer += DH_BYTES;

  memcpy(bufferPointer, ct, DH_BYTES);
  memcpy(bufferPointer + DH_BYTES, pk, DH_BYTES);

  sha3_256(ss, buffer, XWING_PRFINPUT);
  return 0;
}

/*************************************************
 * Name:        crypto_xkem_enc
 *
 * Description: Generates cipher text and shared
 *              secret for given public key
 *
 * Arguments:   - unsigned char *ct:          pointer to output ciphertext (of length XWING_CIPHERTEXTBYTES bytes)
 *              - unsigned char *ss:          pointer to output decrypted message (of length XWING_SSBYTES bytes)
 **************************************************/
int crypto_xkem_enc(unsigned char *ct,
                     unsigned char *ss,
                     const unsigned char *pk)
{
  unsigned char buf[2 * DH_BYTES];
  randombytes(buf, 2 * DH_BYTES);

  return crypto_xkem_enc_derand(ct, ss, pk, buf);
}

/*************************************************
 * Name:        crypto_xkem_dec
 *
 * Description: Generates shared secret for given
 *              cipher text and private key
 *
 * Arguments:   - unsigned char *ss:        pointer to output decrypted message (of length XWING_SSBYTES bytes)
 *              - const unsigned char *ct:  pointer to input ciphertext (of length XWING_CIPHERTEXTKEYBYTES bytes)
 *              - const unsigned char *sk:  pointer to input secret key (of length XWING_SECRETKEYBYTES bytes)
 **************************************************/
int crypto_xkem_dec(uint8_t *ss,
                     const uint8_t *ct,
                     const uint8_t *sk)
{
  unsigned char buffer[XWING_PRFINPUT];
  unsigned char *bufferPointer = buffer;

  memcpy(bufferPointer, XWING_LABEL, 6);
  bufferPointer += 6;

  crypto_mlkem_dec(bufferPointer, ct, sk);

  sk += MLKEM_SECRETKEYBYTES;
  ct += MLKEM_CIPHERTEXTBYTES;
  bufferPointer += MLKEM_SSBYTES;

  lib25519_dh(bufferPointer, ct, sk);
  sk += DH_BYTES;
  bufferPointer += DH_BYTES;

  memcpy(bufferPointer, ct, DH_BYTES);
  memcpy(bufferPointer + DH_BYTES, sk, DH_BYTES);

  sha3_256(ss, buffer, XWING_PRFINPUT);
  return 0;
}
