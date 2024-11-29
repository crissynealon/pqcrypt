#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>
#include "kem.h"


static int handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    return 1;
}

// Generate key pair for RSA KEM
int PQCRYPT_crypto_rsakem_keypair(unsigned char *pk, unsigned char *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov)
		return handle_openssl_error();

    // Generate RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
		return handle_openssl_error();

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return handle_openssl_error();
    }

    EVP_PKEY *keypair = NULL;
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return handle_openssl_error();
    }

    // Get public key in DER format
    unsigned char *temp_pk = NULL;
    int pk_len = i2d_RSAPublicKey(EVP_PKEY_get1_RSA(keypair), &temp_pk);
    if (pk_len > PQCRYPT_CRYPTO_PUBLICKEYBYTES) {
        OPENSSL_free(temp_pk);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
	memset(pk, 0, PQCRYPT_CRYPTO_PUBLICKEYBYTES);
	memcpy(pk, temp_pk, pk_len);
    OPENSSL_free(temp_pk);

	unsigned char *temp_sk = NULL;
    // Get private key in DER format
    int sk_len = i2d_RSAPrivateKey(EVP_PKEY_get1_RSA(keypair), &temp_sk);
    if (sk_len > PQCRYPT_CRYPTO_SECRETKEYBYTES) {
        OPENSSL_free(temp_sk);
        EVP_PKEY_free(keypair);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
	memset(sk, 0, PQCRYPT_CRYPTO_SECRETKEYBYTES);
	memcpy(sk, temp_sk, sk_len);
    OPENSSL_free(temp_sk);

    EVP_PKEY_free(keypair);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// Encapsulate function for RSA KEM
int PQCRYPT_crypto_rsakem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov) return handle_openssl_error();

    const unsigned char *pk_ptr = pk;
    RSA *rsa_pubkey = d2i_RSAPublicKey(NULL, &pk_ptr, PQCRYPT_CRYPTO_PUBLICKEYBYTES);
    if (!rsa_pubkey) return handle_openssl_error();

    // Manually assign the RSA public key to an EVP_PKEY structure
    EVP_PKEY *pubkey = EVP_PKEY_new();
    if (!pubkey) {
        RSA_free(rsa_pubkey);
        return handle_openssl_error();
    }
    if (EVP_PKEY_assign_RSA(pubkey, rsa_pubkey) <= 0) {
        EVP_PKEY_free(pubkey);
        RSA_free(rsa_pubkey);
        return handle_openssl_error();
    }

    EVP_PKEY_CTX *kem_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, "provider=default");
    if (!kem_ctx) {
        EVP_PKEY_free(pubkey);
        return handle_openssl_error();
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "RSASVE", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_encapsulate_init(kem_ctx, params) <= 0) {
        EVP_PKEY_CTX_free(kem_ctx);
        EVP_PKEY_free(pubkey);
        return handle_openssl_error();
    }

    size_t ct_len = PQCRYPT_CRYPTO_CIPHERTEXTBYTES;
    size_t ss_len = PQCRYPT_CRYPTO_BYTES;

    if (EVP_PKEY_encapsulate(kem_ctx, ct, &ct_len, ss, &ss_len) <= 0 ||
        ct_len != PQCRYPT_CRYPTO_CIPHERTEXTBYTES || ss_len != PQCRYPT_CRYPTO_BYTES) {
        EVP_PKEY_CTX_free(kem_ctx);
        EVP_PKEY_free(pubkey);
        return handle_openssl_error();
    }

    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_free(pubkey);
    return 0;
}

// Decapsulate function for RSA KEM
int PQCRYPT_crypto_rsakem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
    if (!defprov)
        return handle_openssl_error();

    const unsigned char *sk_ptr = sk;
    RSA *rsa_privkey = d2i_RSAPrivateKey(NULL, &sk_ptr, PQCRYPT_CRYPTO_SECRETKEYBYTES);
    if (!rsa_privkey)
        return handle_openssl_error();

    // Manually assign the RSA private key to an EVP_PKEY structure
    EVP_PKEY *privkey = EVP_PKEY_new();
    if (!privkey) {
        RSA_free(rsa_privkey);
        return handle_openssl_error();
    }
    if (EVP_PKEY_assign_RSA(privkey, rsa_privkey) <= 0) {
        EVP_PKEY_free(privkey);
        RSA_free(rsa_privkey);
        return handle_openssl_error();
    }

    EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=default");
    if (!dec_ctx) {
        EVP_PKEY_free(privkey);
        return handle_openssl_error();
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, "RSASVE", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_decapsulate_init(dec_ctx, params) <= 0) {
        EVP_PKEY_CTX_free(dec_ctx);
        EVP_PKEY_free(privkey);
        return handle_openssl_error();
    }

    size_t ss_len = PQCRYPT_CRYPTO_BYTES;
    if (EVP_PKEY_decapsulate(dec_ctx, ss, &ss_len, ct, PQCRYPT_CRYPTO_CIPHERTEXTBYTES) <= 0 ||
        ss_len != PQCRYPT_CRYPTO_BYTES) {
        EVP_PKEY_CTX_free(dec_ctx);
        EVP_PKEY_free(privkey);
        return handle_openssl_error();
    }

    EVP_PKEY_CTX_free(dec_ctx);
    EVP_PKEY_free(privkey);
    return 0;
}