#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include "pqcrypt.h"

int PQCRYPT_rsakem_encrypt(uint8_t *ct, const uint8_t *pt, const uint8_t *pk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    const unsigned char *pk_ptr = pk;
    RSA *rsa_pubkey = d2i_RSAPublicKey(NULL, &pk_ptr, PQCRYPT_CRYPTO_PUBLICKEYBYTES);
    if (!rsa_pubkey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Manually assign the RSA public key to an EVP_PKEY structure
    EVP_PKEY *pubkey = EVP_PKEY_new();
    if (!pubkey) {
        RSA_free(rsa_pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (EVP_PKEY_assign_RSA(pubkey, rsa_pubkey) <= 0) {
        EVP_PKEY_free(pubkey);
        RSA_free(rsa_pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=default");
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    size_t outlen = PQCRYPT_CRYPTO_CIPHERTEXTBYTES;
    if (EVP_PKEY_encrypt(ctx, ct, &outlen, pt, PQCRYPT_CRYPTO_PLAINTEXTBYTES) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return 0;
}

int PQCRYPT_rsakem_decrypt(uint8_t *pt, const uint8_t *ct, const uint8_t *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    const unsigned char *sk_ptr = sk;
    RSA *rsa_privkey = d2i_RSAPrivateKey(NULL, &sk_ptr, PQCRYPT_CRYPTO_SECRETKEYBYTES);
    if (!rsa_privkey) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Manually assign the RSA private key to an EVP_PKEY structure
    EVP_PKEY *privkey = EVP_PKEY_new();
    if (!privkey) {
        RSA_free(rsa_privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (EVP_PKEY_assign_RSA(privkey, rsa_privkey) <= 0) {
        EVP_PKEY_free(privkey);
        RSA_free(rsa_privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=default");
    if (!ctx) {
        EVP_PKEY_free(privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    size_t outlen = PQCRYPT_CRYPTO_BYTES;
    if (EVP_PKEY_decrypt(ctx, pt, &outlen, ct, PQCRYPT_CRYPTO_CIPHERTEXTBYTES) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);
    return 0;
}